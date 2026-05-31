CREATE TABLE users (
  id TEXT PRIMARY KEY,                
  username TEXT UNIQUE NOT NULL,      
  password_hash TEXT NOT NULL,        
  display_name TEXT,                  
  created_at INTEGER NOT NULL        
);

CREATE TABLE sessions (
  token TEXT PRIMARY KEY,             
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,        
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE projects (
  id TEXT PRIMARY KEY,               
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,                   
  created_at INTEGER NOT NULL,        
  updated_at INTEGER NOT NULL,        
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE tasks (
  id TEXT PRIMARY KEY,                
  user_id TEXT NOT NULL,
  project_id TEXT NOT NULL,         
  name TEXT NOT NULL,                 
  description TEXT,                  
  priority TEXT CHECK(priority IN ('high', 'medium', 'low')),
  status TEXT CHECK(status IN ('todo', 'doing', 'done')),
  created_at INTEGER NOT NULL,        
  updated_at INTEGER NOT NULL,       
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE docs (
  id TEXT PRIMARY KEY,                
  user_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  title TEXT NOT NULL,
  content TEXT,                       
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX idx_projects_user_id ON projects(user_id);
CREATE INDEX idx_tasks_user_project ON tasks(user_id, project_id);
CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_docs_user_project ON docs(user_id, project_id);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);