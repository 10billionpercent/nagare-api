import { Hono, Context } from "hono";
import { cors } from "hono/cors";
import { v4 as uuidv4 } from "uuid";
import * as bcrypt from "bcryptjs";

// ---------- Types ----------
type User = {
  id: string;
  username: string;
  display_name: string | null;
  created_at: number;
};

type Project = {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  created_at: number;
  updated_at: number;
};

type Task = {
  id: string;
  user_id: string;
  project_id: string;
  name: string;
  description: string | null;
  priority: "high" | "medium" | "low";
  status: "todo" | "doing" | "done";
  created_at: number;
  updated_at: number;
};

type Doc = {
  id: string;
  user_id: string;
  project_id: string;
  title: string;
  content: string | null;
  created_at: number;
  updated_at: number;
};

// Environment bindings + Variables
type Bindings = {
  DB: D1Database;
  PHRASES_KV: KVNamespace;
};

type Variables = {
  user: User;
};

type Env = { Bindings: Bindings; Variables: Variables };

const app = new Hono<Env>();

// ---------- CORS ----------
app.use(
  "/*",
  cors({
    origin: ["http://localhost:5173", "https://nagare-kanban.pages.dev"],
    credentials: true,
  }),
);

async function getUser(c: Context<Env>): Promise<User | null> {
  const token = c.req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return null;

  const session = await c.env.DB.prepare(
    "SELECT user_id, expires_at FROM sessions WHERE token = ?",
  )
    .bind(token)
    .first<{ user_id: string; expires_at: number }>();

  if (!session || session.expires_at < Date.now()) return null;

  const user = await c.env.DB.prepare(
    "SELECT id, username, display_name, created_at FROM users WHERE id = ?",
  )
    .bind(session.user_id)
    .first<User>();

  return user ?? null;
}

// Auth middleware
async function authMiddleware(c: Context<Env>, next: () => Promise<void>) {
  const user = await getUser(c);
  if (!user) return c.text("Unauthorized", 401);
  c.set("user", user);
  await next();
}

// ---------- AUTH ROUTES ----------
app.post("/auth/register", async (c) => {
  const { username, password, display_name } = await c.req.json();
  if (!username || !password)
    return c.text("Username and password required", 400);

  const existing = await c.env.DB.prepare(
    "SELECT id FROM users WHERE username = ?",
  )
    .bind(username)
    .first();
  if (existing) return c.text("Username already taken", 409);

  const userId = uuidv4();
  const hashedPassword = await bcrypt.hash(password, 10);
  const now = Date.now();

  await c.env.DB.prepare(
    "INSERT INTO users (id, username, password_hash, display_name, created_at) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(userId, username, hashedPassword, display_name || username, now)
    .run();

  const token = uuidv4();
  const expiresAt = now + 30 * 24 * 60 * 60 * 1000;
  await c.env.DB.prepare(
    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
  )
    .bind(token, userId, expiresAt)
    .run();

  return c.json({
    token,
    user: { id: userId, username, display_name: display_name || username },
  });
});

app.post("/auth/login", async (c) => {
  const { username, password } = await c.req.json();
  if (!username || !password)
    return c.text("Username and password required", 400);

  const user = await c.env.DB.prepare(
    "SELECT id, username, password_hash, display_name FROM users WHERE username = ?",
  )
    .bind(username)
    .first<{
      id: string;
      username: string;
      password_hash: string;
      display_name: string | null;
    }>();

  if (!user) return c.text("Invalid credentials", 401);

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return c.text("Invalid credentials", 401);

  const token = uuidv4();
  const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
  await c.env.DB.prepare(
    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
  )
    .bind(token, user.id, expiresAt)
    .run();

  return c.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      display_name: user.display_name,
    },
  });
});

app.post("/auth/logout", async (c) => {
  const token = c.req.header("Authorization")?.replace("Bearer ", "");
  if (token) {
    await c.env.DB.prepare("DELETE FROM sessions WHERE token = ?")
      .bind(token)
      .run();
  }
  return c.json({ success: true });
});

app.get("/auth/me", async (c) => {
  const user = await getUser(c);
  if (!user) return c.json(null, 401);
  return c.json({
    id: user.id,
    username: user.username,
    display_name: user.display_name,
  });
});

// ---------- PROJECTS ----------
app.use("/projects/*", authMiddleware);

app.get("/projects", async (c) => {
  const user = c.get("user");
  const projects = await c.env.DB.prepare(
    "SELECT * FROM projects WHERE user_id = ? ORDER BY updated_at DESC",
  )
    .bind(user.id)
    .all();
  return c.json(projects.results);
});

app.post("/projects", async (c) => {
  const user = c.get("user");
  const { id, name, description, createdAt, updatedAt } = await c.req.json();
  const now = Date.now();
  await c.env.DB.prepare(
    `INSERT INTO projects (id, user_id, name, description, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET name=excluded.name, description=excluded.description, updated_at=excluded.updated_at`,
  )
    .bind(
      id || uuidv4(),
      user.id,
      name,
      description || null,
      createdAt || now,
      updatedAt || now,
    )
    .run();
  return c.json({ success: true });
});

app.put("/projects/:id", async (c) => {
  const user = c.get("user");
  const id = c.req.param("id");
  const { name, description, updatedAt } = await c.req.json();
  await c.env.DB.prepare(
    "UPDATE projects SET name = ?, description = ?, updated_at = ? WHERE id = ? AND user_id = ?",
  )
    .bind(name, description || null, updatedAt || Date.now(), id, user.id)
    .run();
  return c.json({ success: true });
});

app.delete("/projects/:id", async (c) => {
  const user = c.get("user");
  const id = c.req.param("id");
  await c.env.DB.prepare("DELETE FROM projects WHERE id = ? AND user_id = ?")
    .bind(id, user.id)
    .run();
  return c.json({ success: true });
});

// ---------- TASKS ----------
app.use("/tasks/*", authMiddleware);

app.get("/tasks", async (c) => {
  const user = c.get("user");
  const projectId = c.req.query("projectId");
  let query = "SELECT * FROM tasks WHERE user_id = ?";
  const params: (string | number)[] = [user.id];
  if (projectId) {
    query += " AND project_id = ?";
    params.push(projectId);
  }
  query += " ORDER BY updated_at DESC";
  const tasks = await c.env.DB.prepare(query)
    .bind(...params)
    .all();
  return c.json(tasks.results);
});

app.post("/tasks", async (c) => {
  const user = c.get("user");
  const {
    id,
    project_id,
    name,
    description,
    priority,
    status,
    created_at,
    updated_at,
  } = await c.req.json();
  const now = Date.now();
  await c.env.DB.prepare(
    `INSERT INTO tasks (id, user_id, project_id, name, description, priority, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       name=excluded.name, description=excluded.description, priority=excluded.priority,
       status=excluded.status, updated_at=excluded.updated_at`,
  )
    .bind(
      id || uuidv4(),
      user.id,
      project_id,
      name,
      description || null,
      priority,
      status,
      created_at || now,
      updated_at || now,
    )
    .run();
  return c.json({ success: true });
});

app.put("/tasks/:id", async (c) => {
  const user = c.get("user");
  const id = c.req.param("id");
  const { name, description, priority, status, updated_at } =
    await c.req.json();
  await c.env.DB.prepare(
    `UPDATE tasks SET name=?, description=?, priority=?, status=?, updated_at=?
     WHERE id=? AND user_id=?`,
  )
    .bind(
      name,
      description || null,
      priority,
      status,
      updated_at || Date.now(),
      id,
      user.id,
    )
    .run();
  return c.json({ success: true });
});

app.delete("/tasks/:id", async (c) => {
  const user = c.get("user");
  const id = c.req.param("id");
  await c.env.DB.prepare("DELETE FROM tasks WHERE id=? AND user_id=?")
    .bind(id, user.id)
    .run();
  return c.json({ success: true });
});

// ---------- DOCS ----------
app.use("/docs/*", authMiddleware);

app.get("/docs", async (c) => {
  const user = c.get("user");
  const projectId = c.req.query("projectId");
  let query = "SELECT * FROM docs WHERE user_id = ?";
  const params: (string | number)[] = [user.id];
  if (projectId) {
    query += " AND project_id = ?";
    params.push(projectId);
  }
  query += " ORDER BY updated_at DESC";
  const docs = await c.env.DB.prepare(query)
    .bind(...params)
    .all();
  return c.json(docs.results);
});

app.post("/docs", async (c) => {
  const user = c.get("user");
  const { id, project_id, title, content, created_at, updated_at } =
    await c.req.json();
  const now = Date.now();
  await c.env.DB.prepare(
    `INSERT INTO docs (id, user_id, project_id, title, content, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       title=excluded.title, content=excluded.content, updated_at=excluded.updated_at`,
  )
    .bind(
      id || uuidv4(),
      user.id,
      project_id,
      title,
      content || null,
      created_at || now,
      updated_at || now,
    )
    .run();
  return c.json({ success: true });
});

app.put("/docs/:id", async (c) => {
  const user = c.get("user");
  const id = c.req.param("id");
  const { title, content, updated_at } = await c.req.json();
  await c.env.DB.prepare(
    "UPDATE docs SET title=?, content=?, updated_at=? WHERE id=? AND user_id=?",
  )
    .bind(title, content || null, updated_at || Date.now(), id, user.id)
    .run();
  return c.json({ success: true });
});

app.delete("/docs/:id", async (c) => {
  const user = c.get("user");
  const id = c.req.param("id");
  await c.env.DB.prepare("DELETE FROM docs WHERE id=? AND user_id=?")
    .bind(id, user.id)
    .run();
  return c.json({ success: true });
});

// ---------- SYNC ----------
app.post("/sync", authMiddleware, async (c) => {
  const user = c.get("user");
  const { localProjects, localTasks, localDocs } = await c.req.json();

  const serverProjects = await c.env.DB.prepare(
    "SELECT * FROM projects WHERE user_id = ?",
  )
    .bind(user.id)
    .all();
  const serverTasks = await c.env.DB.prepare(
    "SELECT * FROM tasks WHERE user_id = ?",
  )
    .bind(user.id)
    .all();
  const serverDocs = await c.env.DB.prepare(
    "SELECT * FROM docs WHERE user_id = ?",
  )
    .bind(user.id)
    .all();

  const serverProjMap = new Map(
    serverProjects.results.map((p: any) => [p.id, p]),
  );
  const serverTaskMap = new Map(serverTasks.results.map((t: any) => [t.id, t]));
  const serverDocMap = new Map(serverDocs.results.map((d: any) => [d.id, d]));

  const finalProjects: any[] = [];
  const finalTasks: any[] = [];
  const finalDocs: any[] = [];

  // Merge projects
  for (const local of localProjects) {
    const server = serverProjMap.get(local.id);
    if (!server) {
      await c.env.DB.prepare(
        `INSERT INTO projects (id, user_id, name, description, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          local.id,
          user.id,
          local.name,
          local.description || null,
          local.createdAt,
          local.updatedAt,
        )
        .run();
      finalProjects.push(local);
    } else {
      if (local.updatedAt > server.updated_at) {
        await c.env.DB.prepare(
          "UPDATE projects SET name=?, description=?, updated_at=? WHERE id=? AND user_id=?",
        )
          .bind(
            local.name,
            local.description || null,
            local.updatedAt,
            local.id,
            user.id,
          )
          .run();
        finalProjects.push(local);
      } else {
        finalProjects.push({
          ...server,
          updatedAt: server.updated_at,
          createdAt: server.created_at,
        });
      }
      serverProjMap.delete(local.id);
    }
  }
  for (const server of serverProjMap.values()) {
    finalProjects.push({
      ...server,
      updatedAt: server.updated_at,
      createdAt: server.created_at,
    });
  }

  // Merge tasks
  for (const local of localTasks) {
    const server = serverTaskMap.get(local.id);
    if (!server) {
      await c.env.DB.prepare(
        `INSERT INTO tasks (id, user_id, project_id, name, description, priority, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          local.id,
          user.id,
          local.project_id,
          local.name,
          local.description || null,
          local.priority,
          local.status,
          local.createdAt,
          local.updatedAt,
        )
        .run();
      finalTasks.push(local);
    } else {
      if (local.updatedAt > server.updated_at) {
        await c.env.DB.prepare(
          `UPDATE tasks SET name=?, description=?, priority=?, status=?, updated_at=? WHERE id=? AND user_id=?`,
        )
          .bind(
            local.name,
            local.description || null,
            local.priority,
            local.status,
            local.updatedAt,
            local.id,
            user.id,
          )
          .run();
        finalTasks.push(local);
      } else {
        finalTasks.push({
          ...server,
          updatedAt: server.updated_at,
          createdAt: server.created_at,
        });
      }
      serverTaskMap.delete(local.id);
    }
  }
  for (const server of serverTaskMap.values()) {
    finalTasks.push({
      ...server,
      updatedAt: server.updated_at,
      createdAt: server.created_at,
    });
  }

  // Merge docs
  for (const local of localDocs) {
    const server = serverDocMap.get(local.id);
    if (!server) {
      await c.env.DB.prepare(
        `INSERT INTO docs (id, user_id, project_id, title, content, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          local.id,
          user.id,
          local.project_id,
          local.title,
          local.content || null,
          local.createdAt,
          local.updatedAt,
        )
        .run();
      finalDocs.push(local);
    } else {
      if (local.updatedAt > server.updated_at) {
        await c.env.DB.prepare(
          `UPDATE docs SET title=?, content=?, updated_at=? WHERE id=? AND user_id=?`,
        )
          .bind(
            local.title,
            local.content || null,
            local.updatedAt,
            local.id,
            user.id,
          )
          .run();
        finalDocs.push(local);
      } else {
        finalDocs.push({
          ...server,
          updatedAt: server.updated_at,
          createdAt: server.created_at,
        });
      }
      serverDocMap.delete(local.id);
    }
  }
  for (const server of serverDocMap.values()) {
    finalDocs.push({
      ...server,
      updatedAt: server.updated_at,
      createdAt: server.created_at,
    });
  }

  return c.json({
    projects: finalProjects,
    tasks: finalTasks,
    docs: finalDocs,
  });
});

// ---------- PHRASE ENDPOINT ----------
app.get("/phrase/:bucket", async (c) => {
  const bucket = c.req.param("bucket");
  const phrasesJson = await c.env.PHRASES_KV.get(`phrases:${bucket}`);
  if (!phrasesJson) {
    const fallbacks: Record<string, string[]> = {
      start: ["Start where you are.", "Small steps count.", "Begin now."],
      continue: ["Keep flowing.", "You are making progress.", "Stay on track."],
      finish: ["Almost done.", "Finish strong.", "You can do it."],
      reset: ["Fresh start.", "New cycle.", "Reset and go again."],
    };
    const list = fallbacks[bucket] || ["Keep moving."];
    const random = list[Math.floor(Math.random() * list.length)];
    return c.json({ phrase: random });
  }
  const phrases = JSON.parse(phrasesJson);
  const random = phrases[Math.floor(Math.random() * phrases.length)];
  return c.json({ phrase: random });
});

app.get("/health", (c) => c.json({ status: "ok" }));

export default app;
