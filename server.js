require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const path = require('path');
const session = require('express-session');
const multer = require('multer');

// (ใหม่) เพิ่ม 2 ไลบรารีสำหรับ PromptPay QR
const promptpay = require('promptpay-qr');
const QRCode = require('qrcode');

const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,        // เปลี่ยนเป็น 465
  secure: true,     // ใช้ SSL
  auth: {
    user: 'netzanadonaja@gmail.com',
    pass: 'vcbokbgakcvmyelv'
  }
});



const app = express();

// 1) parse JSON
app.use(express.json());

// 2) static files
app.use(express.static(path.join(__dirname, 'public')));

// 3) session
app.use(session({
  secret: 'my_super_secret_key_12345',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// 4) connect MySQL
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "0982179126",
  database: "tutor_finder"
});
db.connect(err => {
  if (err) {
    console.error("DB connection error:", err);
    return;
  }
  console.log("✅ Connected to MySQL");
});

/* ------------------------------------------------------------------
| ฟังก์ชันเพิ่ม Notification เข้าในตาราง notifications
------------------------------------------------------------------ */
function addNotification(userId, message) {
  const sql = `INSERT INTO notifications (user_id, message) VALUES (?, ?)`;
  db.query(sql, [userId, message], (err) => {
    if (err) {
      console.error("Error adding notification:", err);
    }
  });
}

/* ------------------------------------------------------------------
| Endpoint ดึง Notification / Mark as read
------------------------------------------------------------------ */
app.get('/notifications', (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const sql = `
    SELECT id, message, is_read, created_at
    FROM notifications
    WHERE user_id = ?
    ORDER BY created_at DESC
  `;
  db.query(sql, [userId], (err, rows) => {
    if (err) {
      console.error("Error fetching notifications:", err);
      return res.status(500).json({ message: 'Database error' });
    }
    res.json({ notifications: rows });
  });
});

app.post('/notifications/mark-read', (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const { notificationId } = req.body;
  if (!notificationId) {
    // mark read all
    const sql = `UPDATE notifications SET is_read = 1 WHERE user_id = ?`;
    db.query(sql, [userId], (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'Database error' });
      }
      res.json({ message: 'mark all read success' });
    });
  } else {
    // mark read one
    const sql = `
      UPDATE notifications
      SET is_read = 1
      WHERE id = ? AND user_id = ?
    `;
    db.query(sql, [notificationId, userId], (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'Database error' });
      }
      res.json({ message: 'mark read success' });
    });
  }
});

/* ------------------------------------------------------------------
| multer (upload profile pic)
------------------------------------------------------------------ */
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'public', 'uploads'));
  },
  filename: (req, file, cb) => {
    const userId = req.session.userId || 'guest';
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, userId + '-' + uniqueSuffix + ext);
  }
});
const upload = multer({ storage: storage });

/* ------------------------------------------------------------------
| REGISTER (POST /users)
| - สร้าง user + สร้าง otp_code + otp_expires_at + ส่งเมล
------------------------------------------------------------------ */
app.post('/users', (req, res) => {
  const { email, name, phone, password_hash } = req.body;

  // ตัวอย่างเช็ค domain @ku.th (หากไม่ต้องการ ให้ลบส่วนนี้ออก)
  if (!email.endsWith('@ku.th')) {
    return res.status(400).json({ message: "อีเมลต้องลงท้ายด้วย @ku.th" });
  }
  if (!email || !name || !phone || !password_hash) {
    return res.status(400).json({ message: "ข้อมูลไม่ครบถ้วน" });
  }

  // INSERT user โดยกำหนด is_verified=0
  const insertSql = `
    INSERT INTO users (email, name, phone, password_hash, is_verified)
    VALUES (?, ?, ?, ?, 0)
  `;
  db.query(insertSql, [email, name, phone, bcrypt.hashSync(password_hash, 10)], (err, result) => {
    if (err) {
      console.error("เพิ่มผู้ใช้ผิดพลาด:", err);
      return res.status(500).json({ error: "Database error" });
    }

    // สร้าง OTP 6 หลัก + กำหนดเวลาหมดอายุ (5 นาที)
    const otpCode = '' + Math.floor(100000 + Math.random() * 900000);
    const expires = new Date(Date.now() + 5 * 60 * 1000); // 5 นาที

    // อัปเดต otp_code, otp_expires_at
    const updateSql = `
      UPDATE users
      SET otp_code = ?, otp_expires_at = ?
      WHERE id = ?
    `;
    db.query(updateSql, [otpCode, expires, result.insertId], (err2) => {
      if (err2) {
        console.error("Error updating OTP in users:", err2);
        return res.status(500).json({ message: "Database error (OTP)" });
      }

      // ส่งอีเมลแจ้ง OTP
      const mailOptions = {
        from: 'YOUR_GMAIL@gmail.com', // ตรงกับ user ใน transporter
        to: email,
        subject: 'OTP สำหรับสมัครสมาชิก',
        text: `สวัสดีค่ะ/ครับ\nรหัส OTP ของคุณคือ: ${otpCode}\n(หมดอายุใน 5 นาที)`
      };

      transporter.sendMail(mailOptions, (mailErr, info) => {
        if (mailErr) {
          console.error('Error sending email:', mailErr);
          return res.status(500).json({ message: 'ไม่สามารถส่งอีเมล OTP' });
        }

        return res.json({
          message: 'สมัครสมาชิกสำเร็จแล้ว กรุณายืนยัน OTP ที่ส่งไปยังอีเมล',
          userId: result.insertId
        });
      });
    });
  });
});

/* ------------------------------------------------------------------
| VERIFY-OTP (POST /verify-otp)
| - ตรวจสอบ otp_code + otp_expires_at
------------------------------------------------------------------ */
app.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ message: 'ข้อมูลไม่ครบ (email, otp)' });
  }

  const sqlSelect = `
    SELECT id, otp_code, otp_expires_at, is_verified
    FROM users
    WHERE email = ?
    LIMIT 1
  `;
  db.query(sqlSelect, [email], (err, rows) => {
    if (err) {
      console.error("select user error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    if (rows.length === 0) {
      return res.status(404).json({ message: "ไม่พบผู้ใช้ email นี้" });
    }

    const user = rows[0];
    // ถ้า user ยืนยันไปแล้ว
    if (user.is_verified === 1) {
      return res.status(400).json({ message: "ผู้ใช้นี้ยืนยันอีเมลไปแล้ว" });
    }

    // เช็คว่า OTP ตรงกันไหม
    if (user.otp_code !== otp) {
      return res.status(400).json({ message: "OTP ไม่ถูกต้อง" });
    }

    // เช็คว่า OTP หมดอายุหรือยัง
    const now = new Date();
    if (now > user.otp_expires_at) {
      return res.status(400).json({ message: "OTP หมดอายุแล้ว" });
    }

    // ผ่านหมด -> ยืนยัน is_verified=1
    const sqlUpdate = `
      UPDATE users
      SET is_verified = 1,
          otp_code = NULL,
          otp_expires_at = NULL
      WHERE id = ?
    `;
    db.query(sqlUpdate, [user.id], (err2) => {
      if (err2) {
        console.error("update user is_verified error:", err2);
        return res.status(500).json({ message: "Database error" });
      }
      return res.json({ message: "ยืนยันอีเมลสำเร็จ (OTP ถูกต้อง)" });
    });
  });
});

/* ------------------------------------------------------------------
| LOGIN (POST /login)
| - บังคับให้ is_verified=1 ก่อนล็อกอิน
------------------------------------------------------------------ */
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, rows) => {
    if (err) {
      console.error("เข้าสู่ระบบผิดพลาด:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (rows.length > 0) {
      const user = rows[0];
      if (bcrypt.compareSync(password, user.password_hash)) {

        // ถ้ายังไม่ verify
        if (user.is_verified !== 1) {
          return res.status(400).json({ message: 'กรุณายืนยันอีเมลก่อนเข้าสู่ระบบ' });
        }

        // ผ่าน -> ล็อกอิน
        req.session.userId = user.id;
        req.session.email = user.email;
        return res.json({ message: 'เข้าสู่ระบบสำเร็จ', user });
      } else {
        return res.status(400).json({ message: 'รหัสผ่านไม่ถูกต้อง' });
      }
    } else {
      return res.status(400).json({ message: 'อีเมลไม่ถูกต้อง' });
    }
  });
});

/* ------------------------------------------------------------------
| UPDATE PROFILE (POST /update-profile)
------------------------------------------------------------------ */
app.post('/update-profile', (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const {
    category,
    description,
    subjects,
    hourlyRate,
    groupRate,
    contactInfo,
    location,
    subjectRates
  } = req.body;

  if (!category || !description || !subjects || !hourlyRate || !groupRate || !contactInfo || !location) {
    return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบ' });
  }

  db.query('SELECT * FROM tutor_profiles WHERE user_id = ?', [userId], (err, rows) => {
    if (err) {
      console.error("ตรวจสอบโปรไฟล์ผิดพลาด:", err);
      return res.status(500).json({ message: 'Database error' });
    }

    if (rows.length === 0) {
      // INSERT
      const insertSql = `
        INSERT INTO tutor_profiles
          (user_id, category, description, subjects, hourly_rate, group_rate,
           contact_info, location, subject_rates)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      db.query(insertSql, [
        userId, category, description, subjects,
        hourlyRate, groupRate, contactInfo, location,
        subjectRates || null
      ], (err2) => {
        if (err2) {
          console.error("เพิ่มโปรไฟล์ผิดพลาด:", err2);
          return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเพิ่มโปรไฟล์' });
        }
        // SELECT กลับ
        const selectSql = `
          SELECT u.name, t.*
          FROM tutor_profiles t
          JOIN users u ON t.user_id = u.id
          WHERE t.user_id = ?
        `;
        db.query(selectSql, [userId], (err3, rows3) => {
          if (err3) {
            console.error("ดึงข้อมูลโปรไฟล์หลัง INSERT ผิดพลาด:", err3);
            return res.status(500).json({ message: 'Database error' });
          }
          return res.json({
            message: 'โปรไฟล์ถูกสร้างและอัปเดตสำเร็จ',
            profile: rows3[0]
          });
        });
      });
    } else {
      // UPDATE
      const updateSql = `
        UPDATE tutor_profiles
        SET category = ?, description = ?, subjects = ?, hourly_rate = ?,
            group_rate = ?, contact_info = ?, location = ?,
            subject_rates = ?
        WHERE user_id = ?
      `;
      db.query(updateSql, [
        category, description, subjects, hourlyRate, groupRate,
        contactInfo, location, subjectRates || null,
        userId
      ], (err4) => {
        if (err4) {
          console.error("อัปเดตโปรไฟล์ผิดพลาด:", err4);
          return res.status(500).json({ message: 'Database error' });
        }
        // SELECT กลับ
        const selectSql = `
          SELECT u.name, t.*
          FROM tutor_profiles t
          JOIN users u ON t.user_id = u.id
          WHERE t.user_id = ?
        `;
        db.query(selectSql, [userId], (err5, rows5) => {
          if (err5) {
            console.error("ดึงข้อมูลโปรไฟล์หลัง UPDATE ผิดพลาด:", err5);
            return res.status(500).json({ message: 'Database error' });
          }
          return res.json({
            message: 'โปรไฟล์อัปเดตสำเร็จ',
            profile: rows5[0]
          });
        });
      });
    }
  });
});

/* ------------------------------------------------------------------
| UPLOAD PROFILE PIC (POST /upload-profile-pic)
------------------------------------------------------------------ */
app.post('/upload-profile-pic', upload.single('profilePic'), (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  if (!req.file) {
    return res.status(400).json({ message: 'ไม่พบไฟล์รูป (profilePic)' });
  }

  const filePath = '/uploads/' + req.file.filename;
  const sql = `
    UPDATE tutor_profiles
    SET profile_pic = ?
    WHERE user_id = ?
  `;
  db.query(sql, [filePath, userId], (err, result) => {
    if (err) {
      console.error("บันทึกรูปโปรไฟล์ผิดพลาด:", err);
      return res.status(500).json({ message: 'Database error' });
    }
    res.json({ message: 'อัปโหลดรูปโปรไฟล์สำเร็จ', profilePic: filePath });
  });
});

/* ------------------------------------------------------------------
| GENERATE 3 สัปดาห์ (POST /generate-schedule)
------------------------------------------------------------------ */
app.post('/generate-schedule', (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const todayStr = new Date().toISOString().slice(0, 10);
  const delSql = `
    DELETE FROM tutor_schedule
    WHERE tutor_id = ?
      AND date >= ?
  `;
  db.query(delSql, [userId, todayStr], (errDel) => {
    if (errDel) {
      console.error("ลบ slot อนาคตไม่สำเร็จ:", errDel);
      return res.status(500).json({ message: 'Database error' });
    }

  const daysToGenerate = 21;
  const startDate = new Date();
  let slotData = [];

  for (let i = 0; i < daysToGenerate; i++) {
    let current = new Date(startDate);
    current.setDate(current.getDate() + i);
    let dateString = current.toISOString().slice(0, 10);

    for (let h = 8; h < 24; h++) {
      const start_time = `${String(h).padStart(2,'0')}:00:00`;
      const end_time = `${String(h+1).padStart(2,'0')}:00:00`;
      slotData.push([
        userId,
        dateString,
        start_time,
        end_time,
        'unavailable',
        null
      ]);
    }
  }

  const insSql = `
    INSERT INTO tutor_schedule
      (tutor_id, date, start_time, end_time, status, student_id)
    VALUES ?
  `;
  db.query(insSql, [slotData], (errIns, result) => {
    if (errIns) {
      console.error("insert slot ใหม่ผิดพลาด:", errIns);
      return res.status(500).json({ message: 'Database error' });
    }
    res.json({
      message: 'ลบ slot อนาคต + สร้าง Time Slots 3 สัปดาห์สำเร็จ',
      insertedRows: result.affectedRows
    });
  });
  });
});

/* ------------------------------------------------------------------
| UPDATE-SCHEDULE (POST /update-schedule)
------------------------------------------------------------------ */
app.post('/update-schedule', (req, res) => {
  const tutorId = req.session.userId;
  if (!tutorId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const { date, startTime, endTime, status, subject } = req.body;
  if (!date || !startTime || !endTime || !status) {
    return res.status(400).json({ message: 'ข้อมูลไม่ครบ' });
  }

  const checkSql = `
    SELECT *
    FROM tutor_schedule
    WHERE tutor_id = ?
      AND date = ?
      AND (
          (start_time BETWEEN ? AND ?)
          OR (end_time BETWEEN ? AND ?)
          OR (start_time <= ? AND end_time >= ?)
      )
  `;
  db.query(checkSql, [tutorId, date, startTime, endTime, startTime, endTime, startTime, endTime], (err, rows) => {
    if (err) {
      console.error("ตรวจสอบเวลาผิดพลาด:", err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (rows.length > 0) {
      return res.status(400).json({ message: 'มีตารางเวลาอื่นในช่วงนี้แล้ว' });
    }

    const insSql = `
      INSERT INTO tutor_schedule (tutor_id, date, start_time, end_time, status, subject)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    db.query(insSql, [tutorId, date, startTime, endTime, status, subject || null], (err2) => {
      if (err2) {
        console.error("บันทึกตารางเวลาผิดพลาด:", err2);
        return res.status(500).json({ message: 'Database error' });
      }
      res.json({ message: 'ตารางเวลาของติวเตอร์ถูกเพิ่มสำเร็จ' });
    });
  });
});

/* ------------------------------------------------------------------
| TOGGLE-SLOT (POST /toggle-slot)
------------------------------------------------------------------ */
app.post('/toggle-slot', (req, res) => {
  const tutorId = req.session.userId;
  if (!tutorId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const { slotId, newStatus } = req.body;
  if (!slotId || !newStatus) {
    return res.status(400).json({ message: 'กรุณาระบุ slotId และ newStatus' });
  }

  db.query('SELECT * FROM tutor_schedule WHERE id = ? AND tutor_id = ?', [slotId, tutorId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ message: 'ไม่พบ slot หรือ slot ไม่ใช่ของคุณ' });
    }

    db.query('UPDATE tutor_schedule SET status = ? WHERE id = ?', [newStatus, slotId], (err2) => {
      if (err2) {
        console.error(err2);
        return res.status(500).json({ message: 'Database error' });
      }
      res.json({ message: 'อัปเดตสถานะสำเร็จ' });
    });
  });
});

/* ------------------------------------------------------------------
| BOOK-SLOT (POST /book-slot) (รองรับหลายชั่วโมง)
------------------------------------------------------------------ */
app.post('/book-slot', (req, res) => {
  const studentId = req.session.userId;
  if (!studentId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const { slotId, slotIds, chosenSubject, bookingType } = req.body;
  const bookingCode = 'REQ-' + Date.now();

  db.query('SELECT name FROM users WHERE id = ?', [studentId], (errName, rowsName) => {
    if (errName || rowsName.length === 0) {
      return res.status(500).json({ message: 'ไม่พบข้อมูลผู้ใช้ (student)' });
    }
    const studentName = rowsName[0].name;

    if (Array.isArray(slotIds) && slotIds.length > 0) {
      // จองหลาย slot
      const sqlSelect = 'SELECT * FROM tutor_schedule WHERE id IN (?)';
      db.query(sqlSelect, [slotIds], (err, rows) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: 'Database error' });
        }
        if (rows.length !== slotIds.length) {
          return res.status(404).json({ message: 'บาง slot ไม่พบในระบบ' });
        }
        for (let slot of rows) {
          if (slot.status !== 'available') {
            return res.status(400).json({ message: 'มีบาง slot ไม่ว่าง' });
          }
        }
        const sqlUpdate = `
          UPDATE tutor_schedule
          SET status = 'pending',
              student_id = ?,
              booked_subject = ?,
              booking_type = ?,
              booking_code = ?
          WHERE id IN (?)
        `;
        db.query(sqlUpdate, [studentId, chosenSubject || null, bookingType || null, bookingCode, slotIds], (err2) => {
          if (err2) {
            console.error(err2);
            return res.status(500).json({ message: 'Database error (update slots)' });
          }
          const tutorId = rows[0].tutor_id;
          addNotification(tutorId, `มีคำขอจองหลายชั่วโมงจาก "${studentName}"`);
          res.json({ message: 'ส่งคำขอจองหลาย slot เรียบร้อย (pending)' });
        });
      });
    } else if (slotId) {
      // จอง slot เดียว
      db.query('SELECT * FROM tutor_schedule WHERE id = ?', [slotId], (err, rows) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: 'Database error' });
        }
        if (rows.length === 0) {
          return res.status(404).json({ message: 'ไม่พบ slot นี้' });
        }
        const slot = rows[0];
        if (slot.status !== 'available') {
          return res.status(400).json({ message: 'slot นี้ไม่ว่าง' });
        }

        const updateSql = `
          UPDATE tutor_schedule
          SET status = 'pending',
              student_id = ?,
              booked_subject = ?,
              booking_type = ?,
              booking_code = ?
          WHERE id = ?
        `;
        db.query(updateSql, [studentId, chosenSubject || null, bookingType || null, bookingCode, slotId], (err2) => {
          if (err2) {
            console.error(err2);
            return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการจอง slot' });
          }
          addNotification(slot.tutor_id, `มีคำขอจอง slot เดียวจาก "${studentName}"`);
          res.json({ message: 'ส่งคำขอจองเรียบร้อย (pending)' });
        });
      });
    } else {
      return res.status(400).json({ message: 'ไม่พบ slotId หรือ slotIds' });
    }
  });
});

/* ------------------------------------------------------------------
| CONFIRM-BOOKING (POST /confirm-booking-code)
------------------------------------------------------------------ */
app.post("/confirm-booking-code", (req, res) => {
  const tutorId = req.session.userId;
  if (!tutorId) return res.status(401).json({ message: "กรุณาล็อกอินก่อน" });

  const { bookingCode, action } = req.body;
  if (!bookingCode || !action) {
    return res.status(400).json({ message: "ข้อมูลไม่ครบ (bookingCode, action)" });
  }

  const sqlSelect = `
    SELECT id, student_id
    FROM tutor_schedule
    WHERE tutor_id = ?
      AND booking_code = ?
      AND status = 'pending'
  `;
  db.query(sqlSelect, [tutorId, bookingCode], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error" });
    }
    if (rows.length === 0) {
      return res.status(404).json({ message: "ไม่พบ slot ที่ pending ใน booking_code นี้" });
    }

    const studentId = rows[0].student_id;
    let newStatus;
    if (action === "approve") {
      newStatus = "booked";
    } else if (action === "reject") {
      newStatus = "available";
    } else {
      return res.status(400).json({ message: "action ไม่ถูกต้อง (approve/reject)" });
    }

    let updateSql;
    if (newStatus === "booked") {
      updateSql = `
        UPDATE tutor_schedule
        SET status = 'booked'
        WHERE tutor_id = ?
          AND booking_code = ?
          AND status = 'pending'
      `;
    } else {
      updateSql = `
        UPDATE tutor_schedule
        SET status = 'available',
            student_id = NULL,
            booked_subject = NULL,
            booking_type = NULL,
            booking_code = NULL
        WHERE tutor_id = ?
          AND booking_code = ?
          AND status = 'pending'
      `;
    }

    db.query(updateSql, [tutorId, bookingCode], (err2) => {
      if (err2) {
        console.error(err2);
        return res.status(500).json({ message: "Database error" });
      }

      db.query('SELECT name FROM users WHERE id = ?', [studentId], (errName, rowsName) => {
        if (errName || rowsName.length === 0) {
          console.error(errName);
        }
        const studentName = rowsName && rowsName[0] ? rowsName[0].name : "นักเรียน";

        if (newStatus === "booked") {
          addNotification(studentId, `ติวเตอร์ได้อนุมัติการจองของคุณแล้ว กรุณาชำระเงิน`);
          return res.json({ message: "อนุมัติเรียบร้อย (booked) ทั้งชุด" });
        } else {
          addNotification(studentId, `ติวเตอร์ได้ปฏิเสธการจองของคุณแล้ว`);
          return res.json({ message: "ปฏิเสธเรียบร้อย (กลับเป็น available) ทั้งชุด" });
        }
      });
    });
  });
});

/* ------------------------------------------------------------------
| CANCEL-BOOKING (POST /cancel-booking-code)
------------------------------------------------------------------ */
app.post("/cancel-booking-code", (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ message: "กรุณาล็อกอินก่อน" });

  const { bookingCode } = req.body;
  if (!bookingCode) {
    return res.status(400).json({ message: "กรุณาระบุ bookingCode" });
  }

  const sqlSelect = `
    SELECT 
      ts.id,
      ts.tutor_id,
      ts.student_id,
      ts.status,
      ts.created_at,
      u1.name AS tutor_name,
      u2.name AS student_name
    FROM tutor_schedule ts
      LEFT JOIN users u1 ON ts.tutor_id = u1.id
      LEFT JOIN users u2 ON ts.student_id = u2.id
    WHERE ts.booking_code = ?
      AND (ts.status = 'pending' OR ts.status = 'booked')
    LIMIT 1
  `;
  db.query(sqlSelect, [bookingCode], (err, rows) => {
    if (err) {
      console.error("SELECT booking for cancel error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    if (rows.length === 0) {
      return res.status(404).json({ message: "ไม่พบการจอง (pending/booked) ใน bookingCode นี้" });
    }

    const slot = rows[0];
    const tutorId = slot.tutor_id;
    const studentId = slot.student_id;
    const tutorName = slot.tutor_name || "ติวเตอร์";
    const studentName = slot.student_name || "นักเรียน";

    const isStudent = (userId === studentId);
    const isTutor   = (userId === tutorId);

    if (!isStudent && !isTutor) {
      return res.status(403).json({ message: "คุณไม่ใช่ผู้จองหรือเจ้าของ slot จึงยกเลิกไม่ได้" });
    }

    const createdAt = new Date(slot.created_at);
    const now = new Date();
    const diffMs = now - createdAt;
    const diffDays = diffMs / (1000 * 60 * 60 * 24);

    function processRefundFull() {
      console.log(">> REFUND เต็มจำนวนให้ student_id=", studentId);
    }
    function processRefundNone() {
      console.log(">> NO REFUND, เงินไปติวเตอร์ =", tutorId);
    }

    if (isStudent) {
      // ตัวอย่างเงื่อนไขยกเลิกภายใน 3 วัน -> refund เต็ม
      if (diffDays <= 3) {
        processRefundFull();
      } else {
        processRefundNone();
      }

      const sqlCancel = `
        UPDATE tutor_schedule
        SET
          status = 'available',
          student_id = NULL,
          booked_subject = NULL,
          booking_type = NULL,
          booking_code = NULL
        WHERE booking_code = ?
          AND (status='pending' OR status='booked')
      `;
      db.query(sqlCancel, [bookingCode], (err2) => {
        if (err2) {
          console.error("cancel update error:", err2);
          return res.status(500).json({ message: "Database error (cancel update)" });
        }
        addNotification(tutorId, `นักเรียน "${studentName}" ได้ยกเลิกการจอง (bookingCode=${bookingCode})`);
        return res.json({ message: "นักเรียนยกเลิกการจองสำเร็จ (slot กลับเป็น available)" });
      });

    } else if (isTutor) {
      // ติวเตอร์ยกเลิก -> refund เต็ม
      processRefundFull();

      const sqlCancel = `
        UPDATE tutor_schedule
        SET
          status = 'available',
          student_id = NULL,
          booked_subject = NULL,
          booking_type = NULL,
          booking_code = NULL
        WHERE booking_code = ?
          AND (status='pending' OR status='booked')
      `;
      db.query(sqlCancel, [bookingCode], (err3) => {
        if (err3) {
          console.error("cancel update error:", err3);
          return res.status(500).json({ message: "Database error (cancel update)" });
        }
        addNotification(studentId, `ติวเตอร์ "${tutorName}" ได้ยกเลิกการจอง (bookingCode=${bookingCode})`);
        return res.json({ message: "ติวเตอร์ยกเลิกการจองสำเร็จ (slot กลับเป็น available)" });
      });
    }
  });
});

/* ------------------------------------------------------------------
| GET-SCHEDULE (GET /get-schedule)
------------------------------------------------------------------ */
app.get('/get-schedule', (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const sql = `
    SELECT
      id,
      tutor_id,
      DATE_FORMAT(date, '%Y-%m-%d') AS date,
      TIME_FORMAT(start_time, '%H:%i') AS start_time,
      TIME_FORMAT(end_time, '%H:%i')   AS end_time,
      status,
      student_id,
      booked_subject,
      booking_type
    FROM tutor_schedule
    WHERE tutor_id = ?
    ORDER BY date, start_time
  `;
  db.query(sql, [userId], (err, rows) => {
    if (err) {
      console.error("ดึงตารางเวลา error:", err);
      return res.status(500).json({ message: 'Database error' });
    }
    res.json({ schedule: rows });
  });
});

/* ------------------------------------------------------------------
| GET /api/tutor-schedule/:tutorId
------------------------------------------------------------------ */
app.get('/api/tutor-schedule/:tutorId', (req, res) => {
  const tutorId = req.params.tutorId;
  const sql = `
    SELECT
      id,
      tutor_id,
      DATE_FORMAT(date, '%Y-%m-%d') AS date,
      TIME_FORMAT(start_time, '%H:%i') AS start_time,
      TIME_FORMAT(end_time, '%H:%i')   AS end_time,
      status,
      student_id,
      booked_subject,
      booking_type
    FROM tutor_schedule
    WHERE tutor_id = ?
    ORDER BY date, start_time
  `;
  db.query(sql, [tutorId], (err, rows) => {
    if (err) {
      console.error("ดึงตารางสอนของติวเตอร์ผิดพลาด:", err);
      return res.status(500).json({ message: 'Database error' });
    }
    res.json({ schedule: rows });
  });
});

/* ------------------------------------------------------------------
| GET /api/single-slot/:slotId
------------------------------------------------------------------ */
app.get('/api/single-slot/:slotId', (req, res) => {
  const slotId = req.params.slotId;
  const sql = `
    SELECT
      id,
      tutor_id,
      DATE_FORMAT(date, '%Y-%m-%d') AS date,
      TIME_FORMAT(start_time, '%H:%i') AS start_time,
      TIME_FORMAT(end_time, '%H:%i')   AS end_time,
      status
    FROM tutor_schedule
    WHERE id = ?
  `;
  db.query(sql, [slotId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ message: 'ไม่พบ Slot' });
    }
    res.json({ slot: rows[0] });
  });
});

/* ------------------------------------------------------------------
| GET /api/tutor/:tutorId
| GET /tutor-profile/:tutorId
------------------------------------------------------------------ */
app.get('/api/tutor/:tutorId', (req, res) => {
  const tutorId = req.params.tutorId;
  const sql = `
    SELECT u.name, t.category, t.description, t.subjects, t.hourly_rate, t.group_rate,
           t.contact_info, t.location, t.profile_pic, t.subject_rates
    FROM users u
    LEFT JOIN tutor_profiles t ON u.id = t.user_id
    WHERE u.id = ?
  `;
  db.query(sql, [tutorId], (err, rows) => {
    if (err) {
      console.error("ดึงโปรไฟล์ติวเตอร์ error:", err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (rows.length > 0) {
      res.json({ profile: rows[0] });
    } else {
      res.status(404).json({ message: 'ไม่พบข้อมูลโปรไฟล์ติวเตอร์' });
    }
  });
});

app.get('/tutor-profile/:tutorId', (req, res) => {
  res.sendFile(path.join(__dirname, 'view', 'tutorProfile.html'));
});

/* ------------------------------------------------------------------
| PROFILE ของตัวเอง (GET /get-profile)
------------------------------------------------------------------ */
app.get('/get-profile', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const userId = req.session.userId;
  const sql = `
    SELECT 
      u.name,
      t.category,
      t.description,
      t.subjects,
      t.hourly_rate,
      t.group_rate,
      t.contact_info,
      t.location,
      t.profile_pic,
      t.subject_rates
    FROM users u
    LEFT JOIN tutor_profiles t ON u.id = t.user_id
    WHERE u.id = ?
  `;
  db.query(sql, [userId], (err, rows) => {
    if (err) {
      console.error("ดึงโปรไฟล์ผิดพลาด:", err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (rows.length > 0) {
      res.json({ profile: rows[0] });
    } else {
      res.status(404).json({ message: 'ไม่พบข้อมูลโปรไฟล์' });
    }
  });
});

/* ------------------------------------------------------------------
| STATUS (GET /status)
------------------------------------------------------------------ */
app.get('/status', (req, res) => {
  if (req.session.userId) {
    res.json({
      message: 'ผู้ใช้ล็อกอินอยู่',
      userId: req.session.userId,
      email: req.session.email
    });
  } else {
    res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });
  }
});

/* ------------------------------------------------------------------
| SEARCH, LOGOUT
------------------------------------------------------------------ */
app.get('/search', (req, res) => {
  res.sendFile(path.join(__dirname, 'view', 'search.html'));
});

app.get('/search-tutors', (req, res) => {
  const { category, subject } = req.query;
  if (!category || !subject) {
    return res.status(400).json({ message: "กรุณาเลือกหมวดหมู่และวิชา" });
  }
  const sql = `
    SELECT u.name, t.*
    FROM tutor_profiles t
    JOIN users u ON t.user_id = u.id
    WHERE FIND_IN_SET(?, t.category)
      AND FIND_IN_SET(?, t.subjects)
  `;
  db.query(sql, [category, subject], (err, rows) => {
    if (err) {
      console.error("ค้นหาติวเตอร์ error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    res.json({ tutors: rows });
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการออกจากระบบ' });
    }
    res.json({ message: 'ออกจากระบบสำเร็จ' });
  });
});

/* ------------------------------------------------------------------
| PAGE ROUTES
------------------------------------------------------------------ */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'view', 'index.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'view', 'register.html'));
});

app.get('/login', (req, res) => {
  if (req.session.userId) {
    // ถ้าเข้ามาที่ /login แล้วมี session อยู่ อาจรีไดเรคไปหน้าอื่น
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'view', 'login.html'));
});

app.get('/profile', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'view', 'profile.html'));
});

app.get('/profile/edit', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'view', 'editProfile.html'));
});

app.get('/schedule', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'view', 'schedule.html'));
});

app.get('/booking', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'view', 'booking.html'));
});

app.get('/pending-bookings', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'view', 'pendingBookings.html'));
});

/* ------------------------------------------------------------------
| (ใหม่) /get-pending, /get-pending-grouped, /my-bookings, /api/my-bookings
------------------------------------------------------------------ */
app.get('/get-pending', (req, res) => {
  const tutorId = req.session.userId;
  if (!tutorId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const sql = `
    SELECT 
      ts.id,
      DATE_FORMAT(ts.date, '%Y-%m-%d') AS date,
      TIME_FORMAT(ts.start_time, '%H:%i') AS start_time,
      TIME_FORMAT(ts.end_time, '%H:%i')   AS end_time,
      ts.status,
      ts.student_id,
      u.name AS student_name,
      ts.booked_subject,
      ts.booking_type,
      ts.booking_code
    FROM tutor_schedule ts
    LEFT JOIN users u ON ts.student_id = u.id
    WHERE ts.tutor_id = ?
      AND ts.status = 'pending'
    ORDER BY ts.date, ts.start_time
  `;
  db.query(sql, [tutorId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Database error' });
    }
    res.json({ pending: rows });
  });
});

app.get('/get-pending-grouped', (req, res) => {
  const tutorId = req.session.userId;
  if (!tutorId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const sql = `
    SELECT
      ts.booking_code,
      ts.student_id,
      u.name AS student_name,
      GROUP_CONCAT(DATE_FORMAT(ts.date, '%Y-%m-%d')
                   ORDER BY ts.date, ts.start_time SEPARATOR ', ') AS dates,
      GROUP_CONCAT(
        CONCAT(
          TIME_FORMAT(ts.start_time, '%H:%i'),
          '-',
          TIME_FORMAT(ts.end_time, '%H:%i')
        )
        ORDER BY ts.date, ts.start_time
        SEPARATOR ', '
      ) AS times,
      ts.booked_subject,
      ts.booking_type
    FROM tutor_schedule ts
    JOIN users u ON ts.student_id = u.id
    WHERE ts.tutor_id = ?
      AND ts.status = 'pending'
    GROUP BY 
      ts.booking_code,
      ts.student_id,
      ts.booked_subject,
      ts.booking_type
    ORDER BY 
      MIN(ts.date), MIN(ts.start_time)
  `;
  db.query(sql, [tutorId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Database error' });
    }
    res.json({ pendingGrouped: rows });
  });
});

app.get('/my-bookings', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'view', 'myBookings.html'));
});

app.get('/api/my-bookings', (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const sql = `
    SELECT
      ts.booking_code,
      tutor.name   AS tutor_name,
      student.name AS student_name,
      GROUP_CONCAT(
        DATE_FORMAT(ts.date, '%Y-%m-%d')
        ORDER BY ts.date, ts.start_time
        SEPARATOR ', '
      ) AS dates,
      GROUP_CONCAT(
        CONCAT(
          TIME_FORMAT(ts.start_time, '%H:%i'),
          '-',
          TIME_FORMAT(ts.end_time, '%H:%i')
        )
        ORDER BY ts.date, ts.start_time
        SEPARATOR ', '
      ) AS times,
      MIN(ts.status) AS status,
      ts.booked_subject,
      ts.booking_type,
      ts.tutor_id,
      ts.student_id
    FROM tutor_schedule ts
      JOIN users tutor   ON ts.tutor_id   = tutor.id
      JOIN users student ON ts.student_id = student.id
    WHERE (ts.tutor_id = ? OR ts.student_id = ?)
      AND ts.status IN ('pending','booked','cancelled')
    GROUP BY
      ts.booking_code,
      ts.tutor_id,
      ts.student_id,
      ts.booked_subject,
      ts.booking_type
    ORDER BY
      MIN(ts.date), MIN(ts.start_time)
  `;
  db.query(sql, [userId, userId], (err, rows) => {
    if (err) {
      console.error("Error fetching my bookings (both sides):", err);
      return res.status(500).json({ message: "Database error" });
    }
    res.json({ bookings: rows });
  });
});

/* ------------------------------------------------------------------
| ฟังก์ชันคำนวณยอดเงิน
------------------------------------------------------------------ */
function calculatePaymentAmount(bookingCode, callback) {
  const sql = `
    SELECT 
      ts.id,
      ts.date,
      ts.start_time,
      ts.end_time,
      ts.payment_status,
      tp.hourly_rate
    FROM tutor_schedule ts
    JOIN tutor_profiles tp ON ts.tutor_id = tp.user_id
    WHERE ts.booking_code = ?
      AND (ts.status = 'booked' OR ts.status = 'pending')
    LIMIT 1
  `;
  db.query(sql, [bookingCode], (err, rows) => {
    if (err) return callback(err);
    if (rows.length === 0) {
      return callback(null, { amount: 0, hourlyRate: 0, hours: 0 });
    }

    const hourlyRate = rows[0].hourly_rate;

    const sql2 = `
      SELECT id, date, start_time, end_time
      FROM tutor_schedule
      WHERE booking_code = ?
        AND (status = 'booked' OR status = 'pending')
    `;
    db.query(sql2, [bookingCode], (err2, slotRows) => {
      if (err2) return callback(err2);
      if (slotRows.length === 0) {
        return callback(null, { amount: 0, hourlyRate, hours: 0 });
      }

      let totalHours = 0;
      for (let s of slotRows) {
        const [sh, sm] = s.start_time.split(':').map(Number);
        const [eh, em] = s.end_time.split(':').map(Number);
        let diffMinutes = (eh * 60 + em) - (sh * 60 + sm);
        let hours = diffMinutes / 60;
        if (hours < 0) hours = 0;
        totalHours += hours;
      }

      let amount = totalHours * hourlyRate;
      callback(null, { amount, hourlyRate, hours: totalHours });
    });
  });
}

/* ------------------------------------------------------------------
| GET /api/payment-info?bookingCode=xxx
------------------------------------------------------------------ */
app.get('/api/payment-info', (req, res) => {
  console.log("==> [payment-info] bookingCode from client:", req.query.bookingCode);

  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const { bookingCode } = req.query;
  if (!bookingCode) {
    return res.status(400).json({ message: 'กรุณาระบุ bookingCode' });
  }

  const sqlCheck = `
    SELECT tutor_id, student_id, status, payment_status
    FROM tutor_schedule
    WHERE booking_code = ?
    LIMIT 1
  `;
  db.query(sqlCheck, [bookingCode], (err, rows) => {
    console.log("==> [payment-info] sqlCheck rows:", rows);

    if (err) {
      console.error('payment-info check error:', err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ message: 'ไม่พบ bookingCode นี้', amount: 0 });
    }
    const row = rows[0];
    if (row.student_id !== userId) {
      return res.status(403).json({ message: 'คุณไม่ใช่ผู้เรียนใน booking นี้' });
    }
    if (row.status !== 'booked') {
      return res.status(400).json({ message: `ไม่สามารถชำระได้ (status=${row.status})` });
    }

    calculatePaymentAmount(bookingCode, (errCalc, result) => {
      if (errCalc) {
        console.error('calcPayment error:', errCalc);
        return res.status(500).json({ message: 'Calculate payment error' });
      }
      res.json({
        bookingCode,
        status: row.status,
        payment_status: row.payment_status,
        totalHours: result.hours,
        hourlyRate: result.hourlyRate,
        amount: result.amount
      });
    });
  });
});

/* ------------------------------------------------------------------
| POST /api/confirm-payment
------------------------------------------------------------------ */
app.post('/api/confirm-payment', (req, res) => {
  console.log("==> [confirm-payment] bookingCode from client:", req.body.bookingCode);

  const userId = req.session.userId;
  if (!userId) return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });

  const { bookingCode } = req.body;
  if (!bookingCode) {
    return res.status(400).json({ message: 'กรุณาระบุ bookingCode' });
  }

  const sqlCheck = `
    SELECT tutor_id, student_id, status, payment_status
    FROM tutor_schedule
    WHERE booking_code = ?
    LIMIT 1
  `;
  db.query(sqlCheck, [bookingCode], (err, rows) => {
    console.log("==> [confirm-payment] sqlCheck rows:", rows);

    if (err) {
      console.error('confirm-payment check error:', err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ message: 'ไม่พบ bookingCode นี้' });
    }
    const row = rows[0];
    if (row.student_id !== userId) {
      return res.status(403).json({ message: 'คุณไม่ใช่ผู้เรียนใน booking นี้' });
    }
    if (row.status !== 'booked') {
      return res.status(400).json({ message: `status=${row.status}, ยังไม่พร้อมชำระหรือชำระไปแล้ว` });
    }
    if (row.payment_status === 'paid') {
      return res.status(400).json({ message: 'รายการนี้ชำระเงินแล้ว' });
    }

    const sqlUpdate = `
      UPDATE tutor_schedule
      SET payment_status = 'paid'
      WHERE booking_code = ?
        AND (status = 'booked')
    `;
    db.query(sqlUpdate, [bookingCode], (err2) => {
      if (err2) {
        console.error('confirm-payment update error:', err2);
        return res.status(500).json({ message: 'Database error (update payment_status)' });
      }

      // แจ้งติวเตอร์ว่าผู้เรียนชำระแล้ว
      const tutorId = row.tutor_id;
      addNotification(tutorId, `ผู้เรียนได้ชำระเงินเรียบร้อย (bookingCode=${bookingCode})`);

      return res.json({ message: 'ชำระเงินสำเร็จ (payment_status=paid)' });
    });
  });
});

/* ------------------------------------------------------------------
| PAGE ROUTE: /payment
------------------------------------------------------------------ */
app.get('/payment', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'view', 'payment.html'));
});

/* 
| (ใหม่) เพิ่มการสร้าง PromptPay QR Code (GET /api/payment-qr?bookingCode=...)
*/
app.get('/api/payment-qr', async (req, res) => {
  try {
    console.log("==> [payment-qr] bookingCode from client:", req.query.bookingCode);

    const userId = req.session.userId;
    if (!userId) {
      return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });
    }

    const { bookingCode } = req.query;
    if (!bookingCode) {
      return res.status(400).json({ message: 'กรุณาระบุ bookingCode' });
    }

    const sqlCheck = `
      SELECT tutor_id, student_id, status, payment_status
      FROM tutor_schedule
      WHERE booking_code = ?
      LIMIT 1
    `;
    db.query(sqlCheck, [bookingCode], (errCheck, rowsCheck) => {
      console.log("==> [payment-qr] sqlCheck rowsCheck:", rowsCheck);

      if (errCheck) {
        console.error('payment-qr check error:', errCheck);
        return res.status(500).json({ message: 'Database error' });
      }
      if (!rowsCheck.length) {
        return res.status(404).json({ message: 'ไม่พบ bookingCode นี้' });
      }
      const row = rowsCheck[0];
      if (row.student_id !== userId) {
        return res.status(403).json({ message: 'คุณไม่ใช่ผู้เรียนใน booking นี้' });
      }
      if (row.status !== 'booked') {
        return res.status(400).json({ message: `ยังไม่พร้อมชำระ (status=${row.status})` });
      }

      calculatePaymentAmount(bookingCode, async (errCalc, result) => {
        if (errCalc) {
          console.error('calcPayment error:', errCalc);
          return res.status(500).json({ message: 'Calculate payment error' });
        }
        const amount = result.amount;
        if (amount <= 0) {
          return res.status(400).json({ message: 'ยอดเงินเป็น 0 หรือ booking ไม่มีชั่วโมง' });
        }

        // สร้าง PromptPay Payload
        const mobileNumber = '0971028248'; 
        const payload = promptpay.generatePayload(mobileNumber, { amount });

        // สร้าง QR Code base64
        const options = { type: 'image/png', errorCorrectionLevel: 'M' };
        QRCode.toDataURL(payload, options)
          .then(qrDataUrl => {
            return res.json({
              bookingCode,
              amount,
              qrDataUrl
            });
          })
          .catch(errQr => {
            console.error('Error generating QR code:', errQr);
            return res.status(500).json({ message: 'Error generating QR code' });
          });
      });
    });
  } catch (err) {
    console.error('Error in /api/payment-qr:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* ------------------------------------------------------------------
| START SERVER
------------------------------------------------------------------ */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}`);
});
