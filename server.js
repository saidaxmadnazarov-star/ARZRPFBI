const express=require("express"),session=require("express-session"),Database=require("better-sqlite3");
const app=express(),db=new Database("winslow14.db");
app.use(express.json());app.use(express.urlencoded({extended:true}));
app.use(session({secret:process.env.SESSION_SECRET||"CHANGE_THIS_SECRET",resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:"lax"}}));
app.use(express.static("public"));

db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,login TEXT UNIQUE,password TEXT,name TEXT,rank TEXT,role TEXT);
CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY AUTOINCREMENT,type TEXT,title TEXT,body TEXT,created TEXT,author TEXT);
CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT,login TEXT,action TEXT,created TEXT);`);
if(db.prepare("SELECT COUNT(*) c FROM users").get().c===0){
 const add=db.prepare("INSERT INTO users(login,password,name,rank,role) VALUES(?,?,?,?,?)");
 add.run("admin","admin123","Главный администратор","Директор ФБР","admin");
 add.run("agent","agent123","Имя Фамилия","Специальный агент","agent");
}
const types=["id","recruitment","checks","civilian","police-ciu","emergency-recruitment","emergency-id","news"];
function auth(req,res,next){if(!req.session.user)return res.status(401).json({error:"Не авторизован"});next()}
function admin(req,res,next){if(req.session.user?.role!=="admin")return res.status(403).json({error:"Недостаточно прав"});next()}

app.get("/api/me",auth,(req,res)=>res.json(req.session.user));
app.post("/api/login",(req,res)=>{let u=db.prepare("SELECT * FROM users WHERE login=? AND password=?").get(req.body.login,req.body.password);
 if(!u)return res.status(401).json({error:"Неверный логин или пароль"});delete u.password;req.session.user=u;
 db.prepare("INSERT INTO logs(login,action,created) VALUES(?,?,?)").run(u.login,"Вход в систему",new Date().toLocaleString("ru-RU"));res.json(u)});
app.post("/api/logout",auth,(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/records/:type",auth,(req,res)=>{if(!types.includes(req.params.type))return res.status(404).end();res.json(db.prepare("SELECT * FROM records WHERE type=? ORDER BY id DESC").all(req.params.type))});
app.post("/api/records/:type",auth,admin,(req,res)=>{if(!types.includes(req.params.type))return res.status(404).end();let {title,body}=req.body;if(!title)return res.status(400).json({error:"Введите заголовок"});
 db.prepare("INSERT INTO records(type,title,body,created,author) VALUES(?,?,?,?,?)").run(req.params.type,title,body||"",new Date().toLocaleString("ru-RU"),req.session.user.name);res.json({ok:true})});
app.delete("/api/records/:type/:id",auth,admin,(req,res)=>{db.prepare("DELETE FROM records WHERE type=? AND id=?").run(req.params.type,req.params.id);res.json({ok:true})});

app.get("/api/users",auth,admin,(req,res)=>res.json(db.prepare("SELECT id,login,name,rank,role FROM users").all()));
app.post("/api/users",auth,admin,(req,res)=>{try{db.prepare("INSERT INTO users(login,password,name,rank,role) VALUES(?,?,?,?,?)").run(req.body.login,req.body.password,req.body.name,req.body.rank,req.body.role||"agent");res.json({ok:true})}catch(e){res.status(400).json({error:"Такой логин уже существует"})}});
app.delete("/api/users/:id",auth,admin,(req,res)=>{db.prepare("DELETE FROM users WHERE id=?").run(req.params.id);res.json({ok:true})});
app.get("/api/logs",auth,admin,(req,res)=>res.json(db.prepare("SELECT * FROM logs ORDER BY id DESC LIMIT 100").all()));

app.get("*",(req,res)=>res.sendFile(require("path").join(__dirname,"public","index.html")));
app.listen(3000,()=>console.log("Winslow [14] Portal: http://localhost:3000"));