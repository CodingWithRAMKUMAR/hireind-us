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
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const { data: user, error } = await supabase
            .from('auth_users')
            .select('*')
            .eq('id', decoded.userId)
            .single();

        if (error || !user) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// ================== REGISTER ==================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, full_name, role } = req.body;

        const { data: existingUser } = await supabase
            .from('auth_users')
            .select('id')
            .eq('email', email)
            .single();

        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
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

        if (authError) throw authError;

        if (role === 'student') {
            await supabase.from('students').insert({
                auth_user_id: authUser.id,
                full_name,
                email,
                profile_status: 'active',
                is_actively_looking: true,
                profile_complete: false,
                source: 'manual'
            });
        } else if (role === 'recruiter') {
            await supabase.from('recruiters').insert({
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
        res.status(500).json({ error: error.message });
    }
});

// ================== LOGIN ==================

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const { data: user, error } = await supabase
            .from('auth_users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
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
        res.status(500).json({ error: error.message });
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

        res.json({ success: true, user: req.user, profile });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ================== STUDENT DASHBOARD ==================

app.get('/api/student/dashboard', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.status(403).json({ error: 'Access denied' });
        }

        let { data: student, error } = await supabase
            .from('students')
            .select('*')
            .eq('auth_user_id', req.user.id)
            .single();

        if (error && error.code === 'PGRST116') {
            const { data: newStudent, error: insertError } = await supabase
                .from('students')
                .insert({
                    auth_user_id: req.user.id,
                    full_name: req.user.full_name,
                    email: req.user.email,
                    profile_status: 'active',
                    is_actively_looking: true,
                    profile_complete: false,
                    source: 'manual'
                })
                .select()
                .single();

            if (insertError) {
                return res.status(500).json({ error: 'Failed to create profile' });
            }
            student = newStudent;
        } else if (error) {
            return res.status(500).json({ error: 'Failed to load dashboard' });
        }

        const { data: skills } = await supabase
            .from('student_skills')
            .select('skills(*)')
            .eq('student_id', student.id);

        const { data: resumes } = await supabase
            .from('resume_versions')
            .select('*')
            .eq('student_id', student.id)
            .order('uploaded_at', { ascending: false });

        res.json({
            success: true,
            student,
            stats: { profile_views: student.profile_view_count || 0, recruiter_contacts: 0 },
            skills: skills?.map(s => s.skills) || [],
            resumes: resumes || []
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to load dashboard: ' + error.message });
    }
});

// ================== STUDENT UPDATE ==================

app.post('/api/student/update', authenticateToken, upload.single('resume'), async (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.status(403).json({ error: 'Access denied' });
        }

        let { data: existingStudent, error: fetchError } = await supabase
            .from('students')
            .select('id')
            .eq('auth_user_id', req.user.id)
            .single();

        if (fetchError && fetchError.code === 'PGRST116') {
            const { data: newStudent, error: createError } = await supabase
                .from('students')
                .insert({
                    auth_user_id: req.user.id,
                    full_name: req.user.full_name,
                    email: req.user.email,
                    profile_status: 'active',
                    is_actively_looking: true,
                    profile_complete: false,
                    source: 'manual'
                })
                .select()
                .single();

            if (createError) {
                return res.status(500).json({ error: 'Failed to create profile: ' + createError.message });
            }
            existingStudent = newStudent;
        } else if (fetchError) {
            return res.status(500).json({ error: 'Database error: ' + fetchError.message });
        }

        let resume_url = null;
        if (req.file) {
            const fileName = Date.now() + '-' + req.file.originalname;
            const { error: uploadError } = await supabase.storage
                .from('resumes')
                .upload(fileName, req.file.buffer);

            if (!uploadError) {
                const { data: urlData } = supabase.storage.from('resumes').getPublicUrl(fileName);
                resume_url = urlData.publicUrl;

                await supabase.from('resume_versions').insert({
                    student_id: existingStudent.id,
                    resume_url: resume_url,
                    file_name: req.file.originalname,
                    is_active: true
                });

                await supabase.from('resume_versions')
                    .update({ is_active: false })
                    .eq('student_id', existingStudent.id)
                    .neq('resume_url', resume_url);
            }
        }

        const updateData = {};
        if (req.body.full_name && req.body.full_name !== '') updateData.full_name = req.body.full_name;
        if (req.body.phone !== undefined) updateData.phone = req.body.phone;
        if (req.body.current_city !== undefined) updateData.current_city = req.body.current_city;
        if (req.body.current_state !== undefined) updateData.current_state = req.body.current_state;
        if (req.body.university_name !== undefined) updateData.university_name = req.body.university_name;
        if (req.body.graduation_date && req.body.graduation_date !== '') updateData.graduation_date = req.body.graduation_date;
        if (req.body.visa_type !== undefined) updateData.visa_type = req.body.visa_type;
        if (req.body.linkedin_url !== undefined) updateData.linkedin_url = req.body.linkedin_url;
        if (req.body.github_url !== undefined) updateData.github_url = req.body.github_url;
        if (resume_url) updateData.resume_url = resume_url;

        updateData.is_actively_looking = (req.body.is_actively_looking === 'on' || req.body.is_actively_looking === true);
        updateData.profile_complete = true;
        updateData.last_active = new Date().toISOString();

        const { data: student, error: updateError } = await supabase
            .from('students')
            .update(updateData)
            .eq('id', existingStudent.id)
            .select()
            .single();

        if (updateError) {
            return res.status(500).json({ error: 'Failed to update: ' + updateError.message });
        }

        if (req.body.skills && req.body.skills.trim() !== '') {
            const skillNames = req.body.skills.split(',').map(s => s.trim()).filter(s => s !== '');

            await supabase.from('student_skills').delete().eq('student_id', student.id);

            for (const skillName of skillNames) {
                let { data: skill } = await supabase.from('skills').select('id').eq('skill_name', skillName).single();
                if (!skill) {
                    const { data: newSkill } = await supabase.from('skills').insert({ skill_name: skillName }).select();
                    if (newSkill && newSkill.length > 0) skill = newSkill[0];
                }
                if (skill) {
                    await supabase.from('student_skills').insert({ student_id: student.id, skill_id: skill.id });
                }
            }
        }

        res.json({ success: true, student, message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile: ' + error.message });
    }
});

// ================== RECRUITER SEARCH ==================

app.post('/api/recruiter/search', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { state, visa } = req.body;

        let query = supabase
            .from('students')
            .select('*')
            .eq('profile_status', 'active')
            .eq('is_actively_looking', true);

        if (state && state !== '') query = query.eq('current_state', state);
        if (visa && visa !== '') query = query.eq('visa_type', visa);

        const { data: students, error } = await query;
        if (error) throw error;

        const hiddenStudents = students?.map(s => ({
            id: s.id,
            full_name: s.full_name,
            current_city: s.current_city,
            current_state: s.current_state,
            university_name: s.university_name,
            visa_type: s.visa_type,
            graduation_date: s.graduation_date,
            profile_view_count: s.profile_view_count
        })) || [];

        res.json({ success: true, count: hiddenStudents.length, students: hiddenStudents });
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ error: 'Search failed' });
    }
});

// ================== RECRUITER STATS ==================

app.get('/api/recruiter/stats', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('*')
            .eq('auth_user_id', req.user.id)
            .single();

        const { count: totalStudents } = await supabase
            .from('students')
            .select('*', { count: 'exact', head: true })
            .eq('profile_status', 'active');

        const { count: optStudents } = await supabase
            .from('students')
            .select('*', { count: 'exact', head: true })
            .in('visa_type', ['OPT_1st_year', 'OPT_2nd_year', 'STEM_OPT'])
            .eq('profile_status', 'active');

        res.json({
            success: true,
            totalStudents: totalStudents || 0,
            optStudents: optStudents || 0,
            recruiter: {
                credits: recruiter?.credits_remaining || 10,
                total_hires: recruiter?.total_hires || 0,
                total_contacts: recruiter?.total_contacts || 0
            }
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: 'Failed to get stats' });
    }
});

// ================== VIEW STUDENT PROFILE ==================

app.get('/api/recruiter/student/:studentId', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { studentId } = req.params;

        const { data: student, error } = await supabase
            .from('students')
            .select('*')
            .eq('id', studentId)
            .eq('profile_status', 'active')
            .single();

        if (error || !student) {
            return res.status(404).json({ error: 'Student not found' });
        }

        const { data: skills } = await supabase
            .from('student_skills')
            .select('skills(*)')
            .eq('student_id', student.id);

        const { data: resumes } = await supabase
            .from('resume_versions')
            .select('*')
            .eq('student_id', student.id)
            .order('uploaded_at', { ascending: false });

        await supabase
            .from('students')
            .update({ profile_view_count: (student.profile_view_count || 0) + 1 })
            .eq('id', student.id);

        res.json({
            success: true,
            student: {
                ...student,
                skills: skills?.map(s => s.skills?.skill_name) || [],
                resumes: resumes || []
            }
        });
    } catch (error) {
        console.error('View profile error:', error);
        res.status(500).json({ error: 'Failed to load student' });
    }
});

// ================== RECRUITER CONTACT ==================

app.post('/api/recruiter/contact', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { student_id, message } = req.body;

        const { data: recruiter, error: recruiterError } = await supabase
            .from('recruiters')
            .select('id, credits_remaining, company_name, total_contacts')
            .eq('auth_user_id', req.user.id)
            .single();

        if (recruiterError || !recruiter || recruiter.credits_remaining <= 0) {
            return res.status(400).json({ error: 'No credits remaining' });
        }

        const { data: student } = await supabase
            .from('students')
            .select('auth_user_id')
            .eq('id', student_id)
            .single();

        if (!student) {
            return res.status(404).json({ error: 'Student not found' });
        }

        await supabase
            .from('recruiters')
            .update({
                credits_remaining: recruiter.credits_remaining - 1,
                total_contacts: (recruiter.total_contacts || 0) + 1
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
                message: `${recruiter.company_name} contacted you.`
            });

        res.json({
            success: true,
            credits_remaining: recruiter.credits_remaining - 1
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

// ================== MARK AS HIRED ==================

app.post('/api/recruiter/mark-hired', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { student_id } = req.body;

        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('id, total_hires')
            .eq('auth_user_id', req.user.id)
            .single();

        await supabase
            .from('students')
            .update({
                profile_status: 'hired',
                hired_by_recruiter_id: recruiter?.id,
                hired_at: new Date().toISOString(),
                is_actively_looking: false
            })
            .eq('id', student_id);

        await supabase
            .from('recruiters')
            .update({ total_hires: (recruiter?.total_hires || 0) + 1 })
            .eq('id', recruiter.id);

        res.json({ success: true, message: 'Student marked as hired' });
    } catch (error) {
        console.error('Mark hired error:', error);
        res.status(500).json({ error: 'Failed to mark as hired' });
    }
});

// ================== ADMIN STATS ==================

app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { count: totalStudents } = await supabase
            .from('students')
            .select('*', { count: 'exact', head: true });

        const { count: activeStudents } = await supabase
            .from('students')
            .select('*', { count: 'exact', head: true })
            .eq('profile_status', 'active');

        const { count: totalRecruiters } = await supabase
            .from('recruiters')
            .select('*', { count: 'exact', head: true });

        const { count: totalHires } = await supabase
            .from('students')
            .select('*', { count: 'exact', head: true })
            .eq('profile_status', 'hired');

        res.json({
            success: true,
            stats: {
                totalStudents: totalStudents || 0,
                activeStudents: activeStudents || 0,
                totalRecruiters: totalRecruiters || 0,
                totalHires: totalHires || 0
            }
        });
    } catch (error) {
        console.error('Admin stats error:', error);
        res.status(500).json({ error: 'Failed to get stats' });
    }
});

// ================== ADMIN GET STUDENTS ==================

app.get('/api/admin/students', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { data: students, error } = await supabase
            .from('students')
            .select('*')
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json({ success: true, students: students || [] });
    } catch (error) {
        console.error('Admin students error:', error);
        res.status(500).json({ error: 'Failed to get students' });
    }
});

// ================== BULK CSV UPLOAD ==================

app.post('/api/admin/bulk-upload', authenticateToken, upload.single('csv'), async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        if (!req.file) {
            return res.status(400).json({ error: 'CSV file required' });
        }

        const results = [];
        let added = 0;
        let duplicates = 0;

        const bufferStream = streamifier.createReadStream(req.file.buffer);
        
        bufferStream
            .pipe(csv())
            .on('data', (data) => results.push(data))
            .on('end', async () => {
                for (const row of results) {
                    const { data: existing } = await supabase
                        .from('auth_users')
                        .select('id')
                        .eq('email', row.email)
                        .single();

                    if (existing) {
                        duplicates++;
                        continue;
                    }

                    const tempPassword = Math.random().toString(36).slice(-8);
                    const hashedPassword = await bcrypt.hash(tempPassword, 10);

                    const { data: authUser, error: authError } = await supabase
                        .from('auth_users')
                        .insert({
                            email: row.email,
                            password_hash: hashedPassword,
                            full_name: row.full_name,
                            role: 'student',
                            is_verified: true
                        })
                        .select()
                        .single();

                    if (authError) continue;

                    await supabase.from('students').insert({
                        auth_user_id: authUser.id,
                        full_name: row.full_name,
                        email: row.email,
                        current_city: row.city,
                        current_state: row.state,
                        university_name: row.university,
                        graduation_date: row.graduation_date,
                        visa_type: row.visa_type,
                        profile_status: 'active',
                        is_actively_looking: true,
                        source: 'csv_upload',
                        profile_complete: true
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
        console.error('Bulk upload error:', error);
        res.status(500).json({ error: 'Bulk upload failed' });
    }
});

// ================== GET NOTIFICATIONS ==================

app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const { data: notifications } = await supabase
            .from('notifications')
            .select('*')
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false })
            .limit(50);

        res.json({ success: true, notifications: notifications || [] });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get notifications' });
    }
});

// ================== DOWNLOAD RESUME ==================

app.get('/api/download-resume/:resumeId', authenticateToken, async (req, res) => {
    try {
        const { resumeId } = req.params;

        const { data: resume } = await supabase
            .from('resume_versions')
            .select('*')
            .eq('id', resumeId)
            .single();

        if (!resume) {
            return res.status(404).json({ error: 'Resume not found' });
        }

        res.json({ success: true, download_url: resume.resume_url });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get resume' });
    }
});

// ================== HEALTH CHECK ==================

app.get('/api/health', async (req, res) => {
    try {
        const { error } = await supabase.from('auth_users').select('id').limit(1);
        res.json({
            status: 'healthy',
            database: error ? 'failed' : 'connected',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ status: 'error', error: error.message });
    }
});

// ================== GLOBAL ERROR HANDLER ==================

app.use((err, req, res, next) => {
    console.error('Global Error:', err);
    res.status(500).json({ success: false, error: err.message });
});

// ================== START SERVER ==================

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`✅ All routes ready`);
});
