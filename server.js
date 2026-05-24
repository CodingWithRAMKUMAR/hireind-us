require('dotenv').config();

const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const csv = require('csv-parser');
const streamifier = require('streamifier');

const app = express();
const PORT = process.env.PORT || 3000;

// ================== SUPABASE ==================

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// ================== MIDDLEWARE ==================

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// ================== DEFAULT ROUTE ==================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ================== MULTER CONFIG ==================

const storage = multer.memoryStorage();

const upload = multer({
    storage,
    limits: {
        fileSize: 10 * 1024 * 1024
    }
});

// ================== JWT ==================

function generateToken(userId) {
    return jwt.sign(
        { userId },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
    );
}

// ================== AUTH MIDDLEWARE ==================

const authenticateToken = async (req, res, next) => {

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            error: 'Access token required'
        });
    }

    try {

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        const { data: user, error } = await supabase
            .from('auth_users')
            .select('*')
            .eq('id', decoded.userId)
            .single();

        if (error || !user) {
            return res.status(401).json({
                error: 'Invalid token'
            });
        }

        req.user = user;

        next();

    } catch (error) {

        return res.status(401).json({
            error: 'Invalid or expired token'
        });

    }
};

// ================== REGISTER ==================

app.post('/api/auth/register', async (req, res) => {

    try {

        const {
            email,
            password,
            full_name,
            role
        } = req.body;

        const { data: existingUser } = await supabase
            .from('auth_users')
            .select('id')
            .eq('email', email)
            .single();

        if (existingUser) {
            return res.status(400).json({
                error: 'Email already registered'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const { data: authUser, error: authError } = await supabase
            .from('auth_users')
            .insert({
                email,
                password_hash: hashedPassword,
                full_name,
                role,
                is_verified: true
            })
            .select()
            .single();

        if (authError) {
            throw authError;
        }

        if (role === 'student') {

            await supabase
                .from('students')
                .insert({
                    auth_user_id: authUser.id,
                    full_name,
                    email,
                    profile_status: 'active',
                    is_actively_looking: true,
                    profile_complete: false,
                    source: 'manual'
                });

        } else if (role === 'recruiter') {

            await supabase
                .from('recruiters')
                .insert({
                    auth_user_id: authUser.id,
                    company_name: 'New Company',
                    credits_remaining: 10,
                    total_contacts: 0,
                    total_hires: 0
                });

        }

        const token = generateToken(authUser.id);

        res.json({
            success: true,
            token,
            user: {
                id: authUser.id,
                email: authUser.email,
                full_name: authUser.full_name,
                role: authUser.role
            }
        });

    } catch (error) {

        console.error('Register Error:', error);

        res.status(500).json({
            error: error.message
        });

    }
});

// ================== LOGIN ==================

app.post('/api/auth/login', async (req, res) => {

    try {

        const {
            email,
            password
        } = req.body;

        const { data: user, error } = await supabase
            .from('auth_users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {

            return res.status(401).json({
                error: 'Invalid email or password'
            });

        }

        const validPassword = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!validPassword) {

            return res.status(401).json({
                error: 'Invalid email or password'
            });

        }

        const token = generateToken(user.id);

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                full_name: user.full_name,
                role: user.role
            }
        });

    } catch (error) {

        console.error('Login Error:', error);

        res.status(500).json({
            error: error.message
        });

    }
});

// ================== CURRENT USER ==================

app.get('/api/auth/me', authenticateToken, async (req, res) => {

    try {

        let profile = null;

        if (req.user.role === 'student') {

            const { data } = await supabase
                .from('students')
                .select('*')
                .eq('auth_user_id', req.user.id)
                .single();

            profile = data;

        }

        if (req.user.role === 'recruiter') {

            const { data } = await supabase
                .from('recruiters')
                .select('*')
                .eq('auth_user_id', req.user.id)
                .single();

            profile = data;

        }

        res.json({
            success: true,
            user: req.user,
            profile
        });

    } catch (error) {

        res.status(500).json({
            error: error.message
        });

    }
});

// ================== STUDENT UPDATE ==================

app.post(
    '/api/student/update',
    authenticateToken,
    upload.single('resume'),
    async (req, res) => {

        try {

            if (req.user.role !== 'student') {

                return res.status(403).json({
                    error: 'Access denied'
                });

            }

            const { data: student } = await supabase
                .from('students')
                .select('*')
                .eq('auth_user_id', req.user.id)
                .single();

            if (!student) {

                return res.status(404).json({
                    error: 'Student not found'
                });

            }

            let resume_url = student.resume_url;

            // ================== RESUME UPLOAD ==================

            if (req.file) {

                const fileName =
                    Date.now() + '-' + req.file.originalname;

                const { error: uploadError } =
                    await supabase.storage
                        .from('resumes')
                        .upload(
                            fileName,
                            req.file.buffer,
                            {
                                contentType: req.file.mimetype,
                                upsert: false
                            }
                        );

                if (uploadError) {

                    return res.status(500).json({
                        error: uploadError.message
                    });

                }

                const { data: publicUrlData } =
                    supabase.storage
                        .from('resumes')
                        .getPublicUrl(fileName);

                resume_url = publicUrlData.publicUrl;

                await supabase
                    .from('resume_versions')
                    .insert({
                        student_id: student.id,
                        resume_url,
                        file_name: req.file.originalname,
                        is_active: true
                    });

                await supabase
                    .from('resume_versions')
                    .update({
                        is_active: false
                    })
                    .eq('student_id', student.id)
                    .neq('resume_url', resume_url);

            }

            // ================== UPDATE PROFILE ==================

            const updateData = {
                full_name: req.body.full_name,
                phone: req.body.phone,
                current_city: req.body.current_city,
                current_state: req.body.current_state,
                university_name: req.body.university_name,
                graduation_date: req.body.graduation_date,
                visa_type: req.body.visa_type,
                linkedin_url: req.body.linkedin_url,
                github_url: req.body.github_url,
                resume_url,
                profile_complete: true,
                is_actively_looking:
                    req.body.is_actively_looking === 'true',
                last_active: new Date().toISOString()
            };

            const { data: updatedStudent, error } =
                await supabase
                    .from('students')
                    .update(updateData)
                    .eq('id', student.id)
                    .select()
                    .single();

            if (error) {
                throw error;
            }

            // ================== SKILLS ==================

            if (req.body.skills) {

                const skillsArray = req.body.skills
                    .split(',')
                    .map(skill => skill.trim());

                await supabase
                    .from('student_skills')
                    .delete()
                    .eq('student_id', student.id);

                for (const skillName of skillsArray) {

                    let { data: skill } = await supabase
                        .from('skills')
                        .select('id')
                        .eq('skill_name', skillName)
                        .single();

                    if (!skill) {

                        const { data: newSkill } =
                            await supabase
                                .from('skills')
                                .insert({
                                    skill_name: skillName
                                })
                                .select()
                                .single();

                        skill = newSkill;

                    }

                    await supabase
                        .from('student_skills')
                        .insert({
                            student_id: student.id,
                            skill_id: skill.id
                        });

                }

            }

            res.json({
                success: true,
                student: updatedStudent
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: error.message
            });

        }

    }
);

// ================== RECRUITER CONTACT ==================

app.post(
    '/api/recruiter/contact',
    authenticateToken,
    async (req, res) => {

        try {

            if (req.user.role !== 'recruiter') {

                return res.status(403).json({
                    error: 'Access denied'
                });

            }

            const {
                student_id,
                message
            } = req.body;

            const { data: recruiter } = await supabase
                .from('recruiters')
                .select(
                    'id, credits_remaining, company_name, total_contacts'
                )
                .eq('auth_user_id', req.user.id)
                .single();

            if (
                !recruiter ||
                recruiter.credits_remaining <= 0
            ) {

                return res.status(400).json({
                    error: 'No credits remaining'
                });

            }

            const { data: student } = await supabase
                .from('students')
                .select('auth_user_id')
                .eq('id', student_id)
                .single();

            if (!student) {

                return res.status(404).json({
                    error: 'Student not found'
                });

            }

            await supabase
                .from('recruiters')
                .update({
                    credits_remaining:
                        recruiter.credits_remaining - 1,

                    total_contacts:
                        (recruiter.total_contacts || 0) + 1
                })
                .eq('id', recruiter.id);

            await supabase
                .from('contact_logs')
                .insert({
                    recruiter_id: recruiter.id,
                    student_id,
                    message,
                    contacted_at: new Date().toISOString()
                });

            await supabase
                .from('notifications')
                .insert({
                    user_id: student.auth_user_id,
                    type: 'contact',
                    title: 'Recruiter Contact',
                    message:
                        recruiter.company_name +
                        ' contacted you.'
                });

            res.json({
                success: true,
                credits_remaining:
                    recruiter.credits_remaining - 1
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: error.message
            });

        }

    }
);

// ================== BULK CSV UPLOAD ==================

app.post(
    '/api/admin/bulk-upload',
    authenticateToken,
    upload.single('csv'),
    async (req, res) => {

        try {

            if (req.user.role !== 'admin') {

                return res.status(403).json({
                    error: 'Access denied'
                });

            }

            if (!req.file) {

                return res.status(400).json({
                    error: 'CSV file required'
                });

            }

            const results = [];

            streamifier
                .createReadStream(req.file.buffer)
                .pipe(csv())
                .on('data', (data) => {
                    results.push(data);
                })
                .on('end', async () => {

                    let added = 0;
                    let duplicates = 0;

                    for (const row of results) {

                        const { data: existing } =
                            await supabase
                                .from('auth_users')
                                .select('id')
                                .eq('email', row.email)
                                .single();

                        if (existing) {
                            duplicates++;
                            continue;
                        }

                        const tempPassword =
                            Math.random()
                                .toString(36)
                                .slice(-8);

                        const hashedPassword =
                            await bcrypt.hash(
                                tempPassword,
                                10
                            );

                        const { data: authUser } =
                            await supabase
                                .from('auth_users')
                                .insert({
                                    email: row.email,
                                    password_hash:
                                        hashedPassword,
                                    full_name:
                                        row.full_name,
                                    role: 'student',
                                    is_verified: true
                                })
                                .select()
                                .single();

                        await supabase
                            .from('students')
                            .insert({
                                auth_user_id:
                                    authUser.id,
                                full_name:
                                    row.full_name,
                                email: row.email,
                                current_city:
                                    row.city,
                                current_state:
                                    row.state,
                                university_name:
                                    row.university,
                                graduation_date:
                                    row.graduation_date,
                                visa_type:
                                    row.visa_type,
                                profile_status:
                                    'active',
                                is_actively_looking:
                                    true,
                                source: 'csv_upload',
                                profile_complete:
                                    true
                            });

                        added++;

                    }

                    res.json({
                        success: true,
                        total: results.length,
                        added,
                        duplicates
                    });

                });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: error.message
            });

        }

    }
);

// ================== HEALTH ==================

app.get('/api/health', async (req, res) => {

    try {

        const { error } = await supabase
            .from('auth_users')
            .select('id')
            .limit(1);

        res.json({
            status: 'healthy',
            database: error
                ? 'failed'
                : 'connected',
            timestamp: new Date().toISOString()
        });

    } catch (error) {

        res.status(500).json({
            status: 'error',
            error: error.message
        });

    }

});

// ================== GLOBAL ERROR ==================

app.use((err, req, res, next) => {

    console.error('Global Error:', err);

    res.status(500).json({
        success: false,
        error: err.message
    });

});

// ================== SERVER ==================

app.listen(PORT, () => {

    console.log(
        `🚀 Server running on http://localhost:${PORT}`
    );

    console.log(
        '✅ Server started successfully'
    );

});
