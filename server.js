require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));
app.use('/views', express.static('views'));


const MONGO = process.env.MONGO_URI || 'mongodb://localhost:27017/spaysecure2';
mongoose.connect(MONGO, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(()=>console.log('MongoDB connected'))
  .catch(err=>console.error('MongoDB error', err));


const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  passwordHash: String,
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const accountSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  number: { type: String, unique: true },
  balance: { type: Number, default: 0 }
});
const txSchema = new mongoose.Schema({
  fromAccount: String,
  toAccount: String,
  amount: Number,
  type: String,
  remark: String,
  date: { type: Date, default: Date.now }
});
const otpSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  code: String,
  expiresAt: Date,
  used: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);
const Account = mongoose.model('Account', accountSchema);
const Tx = mongoose.model('Transaction', txSchema);
const OTP = mongoose.model('OTP', otpSchema);

// Helpers
function genAccountNumber(){
  // 12 digit account
  return Math.floor(100000000000 + Math.random()*900000000000).toString();
}
function authMiddleware(req, res, next){
  const token = req.cookies['token'];
  if(!token) return res.status(401).json({ error: 'unauth' });
  try{
    const data = jwt.verify(token, process.env.JWT_SECRET || 'secret_jwt');
    req.user = data;
    next();
  }catch(e){
    return res.status(401).json({ error: 'invalid token' });
  }
}
function adminMiddleware(req,res,next){
  if(!req.user || !req.user.isAdmin) return res.status(403).json({ error:'admin only' });
  next();
}


app.get('/', (req,res)=> res.sendFile(path.join(__dirname,'views','index.html')));
app.get('/signup', (req,res)=> res.sendFile(path.join(__dirname,'views','signup.html')));
app.get('/login', (req,res)=> res.sendFile(path.join(__dirname,'views','login.html')));
app.get('/dashboard', (req,res)=> res.sendFile(path.join(__dirname,'views','dashboard.html')));
app.get('/admin', (req,res)=> res.sendFile(path.join(__dirname,'views','admin.html')));


app.post('/api/signup',
  body('name').isLength({min:2}),
  body('email').isEmail(),
  body('password').isLength({min:6}),
  async (req,res)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { name, email, password } = req.body;
    try{
      const exists = await User.findOne({ email });
      if(exists) return res.status(400).json({ error:'Email exists' });
      const hash = await bcrypt.hash(password, 10);
      const user = await User.create({ name, email, passwordHash: hash });
      const account = await Account.create({ userId: user._id, number: genAccountNumber(), balance: 10000 });
      const token = jwt.sign({ id: user._id, email: user.email, isAdmin: user.isAdmin }, process.env.JWT_SECRET || 'secret_jwt', { expiresIn: '7d' });
      res.cookie('token', token, { httpOnly: true });
      res.json({ ok:true, user:{ id:user._id, name:user.name, email:user.email }, account });
    }catch(e){
      console.error(e);
      res.status(500).json({ error:'server error' });
    }
});


app.post('/api/login', body('email').isEmail(), body('password').exists(), async (req,res)=>{
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if(!user) return res.status(401).json({ error:'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if(!ok) return res.status(401).json({ error:'Invalid credentials' });
  const token = jwt.sign({ id: user._id, email: user.email, isAdmin: user.isAdmin }, process.env.JWT_SECRET || 'secret_jwt', { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true });
  res.json({ ok:true, user:{ id:user._id, name:user.name, email:user.email } });
});


app.post('/api/logout', (req,res)=>{ res.clearCookie('token'); res.json({ ok:true }); });


app.get('/api/dashboard', authMiddleware, async (req,res)=>{
  const user = await User.findById(req.user.id);
  const account = await Account.findOne({ userId: user._id });
  const txs = await Tx.find({ $or: [{ fromAccount: account.number }, { toAccount: account.number }] }).sort({ date:-1 }).limit(50);
  res.json({ user:{ id:user._id, name:user.name, email:user.email }, account, transactions: txs });
});


app.post('/api/transfer/initiate', authMiddleware, async (req,res)=>{
  const { toAccountNumber, amount, remark } = req.body;
  const user = await User.findById(req.user.id);
  const fromAcc = await Account.findOne({ userId: user._id });
  const toAcc = await Account.findOne({ number: toAccountNumber });
  const num = Number(amount);
  if(!toAcc) return res.status(400).json({ error:'Recipient account not found' });
  if(isNaN(num) || num<=0) return res.status(400).json({ error:'Invalid amount' });
  if(fromAcc.balance < num) return res.status(400).json({ error:'Insufficient balance' });
  const code = Math.floor(100000 + Math.random()*900000).toString();
  const otp = await OTP.create({ userId: user._id, code, expiresAt: new Date(Date.now()+5*60*1000) });
  res.json({ ok:true, otpCode: code, msg:'OTP generated (for demo it is returned; in real app send to mobile/email).' });
});


app.post('/api/transfer/verify', authMiddleware, async (req,res)=>{
  const { toAccountNumber, amount, remark, code } = req.body;
  const user = await User.findById(req.user.id);
  const fromAcc = await Account.findOne({ userId: user._id });
  const toAcc = await Account.findOne({ number: toAccountNumber });
  const num = Number(amount);
  if(!toAcc) return res.status(400).json({ error:'Recipient account not found' });
  if(isNaN(num) || num<=0) return res.status(400).json({ error:'Invalid amount' });
  if(fromAcc.balance < num) return res.status(400).json({ error:'Insufficient balance' });
  const otp = await OTP.findOne({ userId: user._id, code, used:false, expiresAt: { $gt: new Date() } });
  if(!otp) return res.status(400).json({ error:'Invalid or expired OTP' });
  otp.used = true; await otp.save();
  fromAcc.balance -= num; toAcc.balance += num;
  await fromAcc.save(); await toAcc.save();
  const tx1 = await Tx.create({ fromAccount: fromAcc.number, toAccount: toAcc.number, amount: num, type:'debit', remark: remark||'' });
  const tx2 = await Tx.create({ fromAccount: fromAcc.number, toAccount: toAcc.number, amount: num, type:'credit', remark: remark||'' });
  res.json({ ok:true, tx:tx1 });
});


app.get('/api/accounts', authMiddleware, async (req,res)=>{
  const acc = await Account.find({}, 'number balance').limit(200);
  res.json(acc);
});


app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req,res)=>{
  const users = await User.find().limit(200);
  res.json(users);
});
app.post('/api/admin/freeze', authMiddleware, adminMiddleware, async (req,res)=>{
  res.json({ ok:true });
});


async function ensureAdmin(){
  const existing = await User.findOne({ email:'admin@bank.local' });
  if(!existing){
    const hash = await bcrypt.hash('admin123', 10);
    const user = await User.create({ name:'Admin', email:'admin@bank.local', passwordHash: hash, isAdmin: true });
    await Account.create({ userId: user._id, number: genAccountNumber(), balance: 1000000 });
    console.log('Created default admin -> admin@bank.local / admin123');
  }
}
ensureAdmin().catch(e=>console.error(e));

app.listen(PORT, ()=> console.log('Server running on port', PORT));
