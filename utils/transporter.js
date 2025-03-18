
const nodemailer = require("nodemailer");


const AUTH_EMAIL = "netzanadonaja@gmail.com"
const AUTH_PASS = "njyg rkds swdi suob"

// const transporter = nodemailer.createTransport({
//     service: "Gmail",
//     secure: true,
//     auth: {
//         user: AUTH_EMAIL,
//         pass: AUTH_PASS,
//     },
// });

const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    service: "gmail",
    auth: {
        user: AUTH_EMAIL,
        pass: AUTH_PASS,
    },
});

transporter.verify((error, success) => {
    if (error) {
        console.error("Transporter error:", error);
    } else {
        console.log("Server is ready to take our messages");
    }
});