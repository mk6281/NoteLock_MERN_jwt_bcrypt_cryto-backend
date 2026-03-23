







# 🔐 NoteLock – Secure Notes & Password Manager

NoteLock is a full-stack web application designed to securely store and manage personal notes and credentials. It ensures data privacy using encryption, authentication, and modern security practices.

---

## 🚀 Features

### 🔑 Authentication

* User Signup & Login
* Password hashing using bcrypt
* JWT-based authentication
* Protected routes

### 📝 Notes Manager

* Add, edit, delete notes
* Encrypted note storage (AES encryption)
* Secure retrieval & decryption

### 🔐 Password Manager

* Store credentials (site, username, password)
* Encrypted password storage
* View / Hide passwords
* Edit & delete credentials

### 🛡️ Security Features

* Password hashing (bcrypt)
* JWT authentication
* AES encryption (CryptoJS)
* Rate limiting (brute-force protection)
* Security headers (Helmet)
* User-based data isolation

---

## 🛠️ Tech Stack

### Frontend

* React.js
* Bootstrap
* Axios
* React Router

### Backend

* Node.js
* Express.js

### Database

* MongoDB (Local / Atlas)

### Security

* bcrypt
* jsonwebtoken (JWT)
* crypto-js
* helmet
* express-rate-limit

---

## 📂 Project Structure

```
notelock/
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│
├── backend/
│   ├── server.js
│   └── package.json
```

---

## ⚙️ Installation & Setup

### 🔹 1. Clone the repository

```bash
git clone https://github.com/your-username/notelock.git
```

---

### 🔹 2. Setup Backend

```bash
cd backend
npm install
```

Create a `.env` file:

```
MONGO_URI=your_mongodb_atlas_url
JWT_SECRET=your_secret_key
SECRET_KEY=your_encryption_key
```

Run backend:

```bash
node server.js
```

---

### 🔹 3. Setup Frontend

```bash
cd frontend
npm install
npm start
```

---

## 🌐 API Endpoints

### 🔑 Auth

* POST `/signup`
* POST `/login`

### 📝 Notes

* POST `/addNote`
* POST `/getNotes`
* POST `/getNoteById`
* POST `/updateNote`
* POST `/deleteNote`

### 🔐 Credentials

* POST `/addCredential`
* POST `/getCredentials`
* POST `/updateCredential`
* POST `/deleteCredential`

---

## 🔒 Security Implementation

* Passwords are hashed using bcrypt
* Notes & credentials are encrypted using AES (CryptoJS)
* JWT tokens used for authentication
* API routes protected via middleware
* Rate limiting to prevent brute-force attacks
* Helmet used for HTTP security headers

---

## 🧪 Testing

* API endpoints tested using Postman
* Manual testing for authentication & CRUD operations
* Security practices verified (JWT, encryption, validation)

---

## 🚀 Deployment

* Frontend: Vercel
* Backend: Render
* Database: MongoDB Atlas

---

## 📸 Screenshots (Optional)

*Add screenshots here for UI preview*

---

## 🎯 Future Enhancements

* Search functionality 🔍
* Password strength checker 💪
* Auto password generator 🔑
* Dark mode 🌙
* Two-factor authentication (2FA)
* CI/CD pipeline

---

## 👨‍💻 Author

**MK (Manikanta Perneedi)**
Full Stack Developer

---

## ⭐ Acknowledgements

* MongoDB Atlas
* Render
* Vercel
* Open-source libraries
