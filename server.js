const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors({}));
app.use(express.urlencoded({ extended: true }));

const jwtSecret = process.env.JWT_SECRET || "defaultSecret";
const SECRET_KEY = process.env.SECRET_KEY;

mongoose.connect(process.env.MONGO_URI, {})
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.error("MongoDB Connection Error:", err));

const TargetSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    patternFileUrl: { type: String, required: true },
    markerUrl: { type: String, required: true },
    objectUrl: { type: String, required: true }
}, { timestamps: true });

const Target = mongoose.model("Target", TargetSchema);

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    role: String,
});

const User = mongoose.model("User", userSchema);

const visitorSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    birthDate: { type: String, required: true },
    phone: { type: String, required: true },
    role: String
}, { timestamps: true });

const Visitor = mongoose.model("Visitor", visitorSchema);

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        if (file.mimetype.startsWith("image/")) {
            return { resource_type: "image" };
        } else if (file.mimetype.startsWith("video/")) {
            return { resource_type: "video" };
        } else if (file.mimetype === "text/plain") {
            return { resource_type: "raw", format: "patt" };
        } else {
            throw new Error("Format file tidak didukung!");
        }
    },
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith("image/") || file.mimetype.startsWith("video/") || file.mimetype === "text/plain") {
            cb(null, true);
        } else {
            cb(new Error("Format file tidak didukung!"), false);
        }
    }
});

app.post(
    "/api/upload",
    upload.fields([{ name: "marker" }, { name: "object" }, { name: "patternFile" }]),
    async (req, res) => {
        try {
            if (!req.files || !req.files.marker || !req.files.object || !req.files.patternFile) {
                return res.status(400).json({ 
                    success: false, 
                    message: "Harap unggah gambar marker, objek (gambar/video), dan file .patt." 
                });
            }

            const { title, description } = req.body;
            if (!title || !description) {
                return res.status(400).json({ 
                    success: false, 
                    message: "Title dan Description wajib diisi!" 
                });
            }

            const patternFileUrl = req.files.patternFile[0].path;
            const markerUrl = req.files.marker[0].path;
            const objectUrl = req.files.object[0].path;

            const newTarget = new Target({
                title,
                description,
                patternFileUrl,
                markerUrl,
                objectUrl
            });

            await newTarget.save();

            res.json({
                success: true,
                message: "File dan data berhasil diunggah.",
                title,
                description,
                patternFileUrl,
                markerUrl,
                objectUrl
            });

        } catch (error) {
            console.error("Error saat mengunggah file:", error);
            res.status(500).json({ success: false, message: "Gagal mengunggah file dan data." });
        }
    }
);

app.get("/api/targets", async (req, res) => {
    try {
        const targets = await Target.find();
        res.json(targets);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
        console.log("User tidak ditemukan");
        return res.status(401).json({ message: "User tidak ditemukan" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        console.log("Password salah");
        return res.status(401).json({ message: "Password salah" });
    }

    const token = jwt.sign({ username: user.username, role: user.role }, jwtSecret, { expiresIn: "30m" });
    res.json({ token });
});

app.post("/api/visitors", async (req, res) => {
    try {
        const { name, email, birthDate, phone } = req.body;

        const existingVisitor = await Visitor.findOne({ email });
        if (existingVisitor) {
            return res.status(400).json({ message: "Email sudah terdaftar" });
        }
    
        const newVisitor = new Visitor({ name, email, birthDate, phone, role: 'visitor' });
        await newVisitor.save();

        const token = jwt.sign({ id: newVisitor._id, email: newVisitor.email, role: 'visitor' }, SECRET_KEY, { expiresIn: "30m" });

        return res.status(201).json({ message: "Visitor berhasil ditambahkan.", visitor: newVisitor, token });
    } catch (error) {
        console.error("Error saat menyimpan visitor:", error);
        return res.status(500).json({ message: "Gagal menyimpan data.", error: error.message });
    }
});

app.post("/api/login", async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ message: "Email harus diisi." });
        }

        const visitor = await Visitor.findOne({ email });
        if (!visitor) {
            return res.status(404).json({ message: "Email tidak ditemukan" });
        }

        const token = jwt.sign({ id: visitor._id, email: visitor.email, role: visitor.role || 'visitor' }, SECRET_KEY, { expiresIn: "30m" });

        return res.status(200).json({ message: "Login berhasil", visitor, token });
    } catch (error) {
        console.error("Error saat login:", error);
        return res.status(500).json({ message: "Terjadi kesalahan", error: error.message });
    }
});


const verifyUserToken = (req, res, next) => {
    const authHeader = req.header("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Akses ditolak, token tidak ditemukan atau format tidak valid" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "Token tidak valid" });
    }

    try {
        const verified = jwt.verify(token, SECRET_KEY);
        req.user = verified;

        if (req.user.role !== 'visitor') {
            return res.status(403).json({ message: "Akses ditolak, hanya pengguna dengan role 'visitor' yang bisa mengakses" });
        }

        next();
    } catch (err) {
        return res.status(403).json({ message: "Token tidak valid atau sudah kedaluwarsa" });
    }
};

app.get("/api/visitors", verifyUserToken, async (req, res) => {
    try {
        const visitors = await Visitor.find();
        res.json(visitors);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching visitors' });
    }
});

app.delete("/api/targets/:id", async (req, res) => {
    try {
        const deletedTarget = await Target.findByIdAndDelete(req.params.id);
        if (!deletedTarget) {
            return res.status(404).json({ message: "Target not found" });
        }
        res.json({ message: "Target deleted successfully" });
    } catch (error) {
        console.error("Error deleting target:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
});

app.get('/api/totalvisitors', async (req, res) => {
    const totalVisitors = await Visitor.countDocuments();
    res.json({ visitors: totalVisitors });
});

app.get('/api/totalmarkers', async (req, res) => {
    const totalMarkers = await Target.countDocuments();
    res.json({ markers: totalMarkers });
});

app.get('/api/marker-count', async (req, res) => {
    try {
        const markers = await Target.find();

        const imageExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
        const videoExtensions = ['mp4', 'webm', 'ogg'];

        let imageCount = 0;
        let videoCount = 0;

        markers.forEach(marker => {
            const fileExt = marker.objectUrl.split('.').pop().toLowerCase();

            if (imageExtensions.includes(fileExt)) {
                imageCount++;
            } else if (videoExtensions.includes(fileExt)) {
                videoCount++;
            }
        });

        res.json({ imageCount, videoCount });
    } catch (error) {
        res.status(500).json({ error: 'Error fetching marker counts' });
    }
});

const verifyAdminToken = (req, res, next) => {
    const authHeader = req.header("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Akses ditolak, token tidak ditemukan atau format tidak valid" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "Token tidak valid" });
    }

    try {
        const verified = jwt.verify(token, jwtSecret);
        req.user = verified;
        
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: "Akses ditolak, hanya admin yang bisa mengakses" });
        }
        
        next();
    } catch (err) {
        return res.status(403).json({ message: "Token tidak valid atau sudah kedaluwarsa" });
    }
};

app.get("/api/admin/dashboard", verifyAdminToken, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.user.username });
        if (!user) return res.status(404).json({ message: "Admin tidak ditemukan" });

        res.json({
            username: user.username,
            role: user.role
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


app.get("/api/user", verifyUserToken, async (req, res) => {
    try {
        const visitor = await Visitor.findOne({ email: req.user.email });
        if (!visitor) return res.status(404).json({ message: "Visitor tidak ditemukan" });

        res.json({
            name: visitor.name,
            email: visitor.email,
            birthDate: visitor.birthDate,
            phone: visitor.phone
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(8080, () => {
    console.log("Server berjalan di http://localhost:8080");
});
