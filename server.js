require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const path = require('path');
const session = require('express-session');
const multer = require('multer');

const app = express();

// 1) parse JSON
app.use(express.json());

// 2) static files in public
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
------------------------------------------------------------------ */
app.post('/users', (req, res) => {
  const { email, name, phone, password_hash } = req.body;

  // ตัวอย่างเช็ค email @ku.th
  if (!email.endsWith('@ku.th')) {
    return res.status(400).json({ message: "อีเมลต้องลงท้ายด้วย @ku.th" });
  }
  if (!email || !name || !phone || !password_hash) {
    return res.status(400).json({ message: "ข้อมูลไม่ครบถ้วน" });
  }

  db.query(
    "INSERT INTO users (email, name, phone, password_hash) VALUES (?, ?, ?, ?)",
    [email, name, phone, bcrypt.hashSync(password_hash, 10)],
    (err, result) => {
      if (err) {
        console.error("เพิ่มผู้ใช้ผิดพลาด:", err);
        return res.status(500).json({ error: "Database error" });
      }
      res.json({ message: "User added successfully", userId: result.insertId });
    }
  );
});


/* ------------------------------------------------------------------
| LOGIN (POST /login)
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
        // login success
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
| เพิ่ม subjectRates (JSON) -> subject_rates (DB)
------------------------------------------------------------------ */
app.post('/update-profile', (req, res) => {
  const userId = req.session.userId;
  if (!userId) {
    return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });
  }

  const {
    category,
    description,
    subjects,
    hourlyRate,
    groupRate,
    contactInfo,
    location,
    subjectRates // JSON string
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
  if (!userId) {
    return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });
  }
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
| ลบ slot อนาคต + สร้างใหม่
------------------------------------------------------------------ */
app.post('/generate-schedule', (req, res) => {
  const userId = req.session.userId;
  if (!userId) {
    return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });
  }

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
  if (!tutorId) {
    return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });
  }

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
  db.query(checkSql, [tutorId, date, startTime, endTime, startTime, endTime, startTime, endTime],
  (err, rows) => {
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
    db.query(insSql, [tutorId, date, startTime, endTime, status, subject || null],
    (err2) => {
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
  if (!tutorId) {
    return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });
  }

  const { slotId, newStatus } = req.body;
  if (!slotId || !newStatus) {
    return res.status(400).json({ message: 'กรุณาระบุ slotId และ newStatus' });
  }

  db.query('SELECT * FROM tutor_schedule WHERE id = ? AND tutor_id = ?', [slotId, tutorId],
  (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ message: 'ไม่พบ slot หรือ slot ไม่ใช่ของคุณ' });
    }

    db.query('UPDATE tutor_schedule SET status = ? WHERE id = ?', [newStatus, slotId],
    (err2) => {
      if (err2) {
        console.error(err2);
        return res.status(500).json({ message: 'Database error' });
      }
      res.json({ message: 'อัปเดตสถานะสำเร็จ' });
    });
  });
});


/* ------------------------------------------------------------------
| BOOK-SLOT (POST /book-slot)
| -> เปลี่ยนเป็น pending + เก็บ subject, bookingType
------------------------------------------------------------------ */
app.post('/book-slot', (req, res) => {
  const studentId = req.session.userId;
  if (!studentId) {
    return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });
  }

  const { slotId, chosenSubject, bookingType } = req.body;
  if (!slotId) {
    return res.status(400).json({ message: 'ไม่พบ slotId' });
  }

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

    // set pending
    const updateSql = `
      UPDATE tutor_schedule
      SET status = 'pending',
          student_id = ?,
          booked_subject = ?,
          booking_type = ?
      WHERE id = ?
    `;
    db.query(updateSql, [studentId, chosenSubject || null, bookingType || null, slotId], (err2) => {
      if (err2) {
        console.error(err2);
        return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการจอง slot' });
      }
      res.json({ message: 'ส่งคำขอจองเรียบร้อย (pending)' });
    });
  });
});


/* ------------------------------------------------------------------
| CONFIRM-BOOKING (POST /confirm-booking)
| ติวเตอร์ approve / reject slot ที่เป็น pending
------------------------------------------------------------------ */
app.post('/confirm-booking', (req, res) => {
  const tutorId = req.session.userId;
  if (!tutorId) {
    return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });
  }

  const { slotId, action } = req.body; // action = "approve" หรือ "reject"
  if (!slotId || !action) {
    return res.status(400).json({ message: 'ข้อมูลไม่ครบ (slotId, action)' });
  }

  db.query('SELECT * FROM tutor_schedule WHERE id = ? AND tutor_id = ?', [slotId, tutorId],
  (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ message: 'ไม่พบ slot หรือ slot ไม่ใช่ของคุณ' });
    }

    const slot = rows[0];
    if (slot.status !== 'pending') {
      return res.status(400).json({ message: 'slot นี้ไม่ได้อยู่ในสถานะ pending' });
    }

    let newStatus;
    if (action === 'approve') {
      newStatus = 'booked'; // อนุมัติ
    } else if (action === 'reject') {
      newStatus = 'available'; // ปฏิเสธ -> กลับเป็น available
    } else {
      return res.status(400).json({ message: 'action ไม่ถูกต้อง (approve/reject)' });
    }

    if (newStatus === 'booked') {
      // approve
      const sqlApprove = `
        UPDATE tutor_schedule
        SET status = 'booked'
        WHERE id = ?
      `;
      db.query(sqlApprove, [slotId], (err2) => {
        if (err2) {
          console.error(err2);
          return res.status(500).json({ message: 'Database error' });
        }
        res.json({ message: 'ยืนยันการจองเรียบร้อย (booked)' });
      });
    } else {
      // reject
      const sqlReject = `
        UPDATE tutor_schedule
        SET status = 'available',
            student_id = NULL,
            booked_subject = NULL,
            booking_type = NULL
        WHERE id = ?
      `;
      db.query(sqlReject, [slotId], (err3) => {
        if (err3) {
          console.error(err3);
          return res.status(500).json({ message: 'Database error' });
        }
        res.json({ message: 'ปฏิเสธการจองเรียบร้อย (กลับเป็น available)' });
      });
    }
  });
});


/* ------------------------------------------------------------------
| GET-SCHEDULE (GET /get-schedule)
| เพิ่ม columns: booked_subject, booking_type
------------------------------------------------------------------ */
app.get('/get-schedule', (req, res) => {
  const userId = req.session.userId;
  if (!userId) {
    return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });
  }

  const sql = `
    SELECT
      id,
      tutor_id,
      date,
      TIME_FORMAT(start_time, '%H:%i:%s') AS start_time,
      TIME_FORMAT(end_time, '%H:%i:%s')   AS end_time,
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
| (ใหม่) GET /api/tutor-schedule/:tutorId
| เพิ่ม columns: booked_subject, booking_type
------------------------------------------------------------------ */
app.get('/api/tutor-schedule/:tutorId', (req, res) => {
  const tutorId = req.params.tutorId;
  const sql = `
    SELECT
      id,
      tutor_id,
      date,
      TIME_FORMAT(start_time, '%H:%i:%s') AS start_time,
      TIME_FORMAT(end_time, '%H:%i:%s')   AS end_time,
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
| PUBLIC TUTOR PROFILE
| GET /api/tutor/:tutorId - ข้อมูลโปรไฟล์ติวเตอร์
| GET /tutor-profile/:tutorId - ส่งไฟล์ HTML หน้าโปรไฟล์
------------------------------------------------------------------ */
app.get('/api/tutor/:tutorId', (req, res) => {
  const tutorId = req.params.tutorId;
  const sql = `
    SELECT u.name, t.category, t.description, t.subjects, t.hourly_rate, t.group_rate,
           t.contact_info, t.location, t.profile_pic,
           t.subject_rates
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
| (สำคัญ) PROFILE ของตัวเอง (GET /get-profile)
| หน้า profile.html เรียก fetch("/get-profile") → ต้องมี route นี้
------------------------------------------------------------------ */
app.get('/get-profile', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });
  }

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
      // ยังไม่มีข้อมูลโปรไฟล์
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
// หน้า index
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'view', 'index.html'));
});

// หน้า register
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'view', 'register.html'));
});

// หน้า login
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'view', 'login.html'));
});

// หน้าโปรไฟล์ (ของตัวเอง)
app.get('/profile', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'view', 'profile.html'));
});

// หน้าแก้ไขโปรไฟล์
app.get('/profile/edit', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'view', 'editProfile.html'));
});

// หน้า schedule
app.get('/schedule', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'view', 'schedule.html'));
});

// หน้า booking
app.get('/booking', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'view', 'booking.html'));
});

// หน้า pendingBookings
app.get('/pending-bookings', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'view', 'pendingBookings.html'));
});


/* ------------------------------------------------------------------
| ดึงรายการ pending (GET /get-pending)
------------------------------------------------------------------ */
app.get('/get-pending', (req, res) => {
  const tutorId = req.session.userId;
  if (!tutorId) {
    return res.status(401).json({ message: 'กรุณาล็อกอินก่อน' });
  }
  const sql = `
    SELECT
      id,
      date,
      TIME_FORMAT(start_time, '%H:%i:%s') AS start_time,
      TIME_FORMAT(end_time, '%H:%i:%s')   AS end_time,
      status,
      student_id,
      booked_subject,
      booking_type
    FROM tutor_schedule
    WHERE tutor_id = ?
      AND status = 'pending'
    ORDER BY date, start_time
  `;
  db.query(sql, [tutorId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Database error' });
    }
    res.json({ pending: rows });
  });
});

// ดึงข้อมูล slot เดี่ยว
app.get('/api/single-slot/:slotId', (req, res) => {
  const slotId = req.params.slotId;
  const sql = `
    SELECT
      id,
      tutor_id,
      date,
      TIME_FORMAT(start_time, '%H:%i:%s') AS start_time,
      TIME_FORMAT(end_time, '%H:%i:%s')   AS end_time,
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
| START SERVER
------------------------------------------------------------------ */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}`);
});
