require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase Client
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Serve login page as default
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// File upload configuration
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// Ensure uploads folder exists
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');

// ========== AUTH MIDDLEWARE ==========
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

function generateToken(userId) {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

// ========== AUTH ROUTES ==========

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, full_name, role } = req.body;
        
        const { data: existing } = await supabase
            .from('auth_users')
            .select('email')
            .eq('email', email)
            .single();
        
        if (existing) {
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
            await supabase
                .from('students')
                .insert({ 
                    auth_user_id: authUser.id, 
                    full_name,
                    email,
                    profile_status: 'active',
                    profile_complete: false
                });
        } else if (role === 'recruiter') {
            await supabase
                .from('recruiters')
                .insert({ 
                    auth_user_id: authUser.id, 
                    company_name: 'New Company',
                    credits_remaining: 10,
                    subscription_tier: 'free'
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
        console.error('Register error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login
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
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    let profile = null;
    
    if (req.user.role === 'student') {
        const { data } = await supabase
            .from('students')
            .select('*')
            .eq('auth_user_id', req.user.id)
            .single();
        profile = data;
    } else if (req.user.role === 'recruiter') {
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
});

// ========== STUDENT ROUTES ==========

// Get student dashboard
app.get('/api/student/dashboard', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { data: student } = await supabase
            .from('students')
            .select('*')
            .eq('auth_user_id', req.user.id)
            .single();
        
        const { count: viewCount } = await supabase
            .from('view_logs')
            .select('*', { count: 'exact', head: true })
            .eq('student_id', student.id);
        
        const { data: skills } = await supabase
            .from('student_skills')
            .select('skills(*)')
            .eq('student_id', student.id);
        
        res.json({
            success: true,
            student,
            stats: {
                profile_views: viewCount || 0
            },
            skills: skills?.map(s => s.skills) || []
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to load dashboard' });
    }
});

// Update student profile
app.post('/api/student/update', authenticateToken, upload.single('resume'), async (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        let resume_url = null;
        if (req.file) {
            const fileName = Date.now() + '-' + req.file.originalname;
            const { error: uploadError } = await supabase.storage
                .from('resumes')
                .upload(fileName, req.file.buffer);
            if (!uploadError) {
                const { data: urlData } = supabase.storage
                    .from('resumes')
                    .getPublicUrl(fileName);
                resume_url = urlData.publicUrl;
            }
        }
        
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
            is_actively_looking: req.body.is_actively_looking === 'on',
            profile_complete: true,
            updated_at: new Date()
        };
        
        if (resume_url) updateData.resume_url = resume_url;
        
        const { data: student, error } = await supabase
            .from('students')
            .update(updateData)
            .eq('auth_user_id', req.user.id)
            .select()
            .single();
        
        if (error) throw error;
        
        // Update skills
        if (req.body.skills) {
            const skillNames = req.body.skills.split(',').map(s => s.trim());
            
            await supabase
                .from('student_skills')
                .delete()
                .eq('student_id', student.id);
            
            for (const skillName of skillNames) {
                let { data: skill } = await supabase
                    .from('skills')
                    .select('id')
                    .eq('skill_name', skillName)
                    .single();
                
                if (!skill) {
                    const { data: newSkill } = await supabase
                        .from('skills')
                        .insert({ skill_name: skillName })
                        .select();
                    skill = newSkill[0];
                }
                
                await supabase
                    .from('student_skills')
                    .insert({ student_id: student.id, skill_id: skill.id });
            }
        }
        
        res.json({ success: true, student });
        
    } catch (error) {
        console.error('Update error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// ========== RECRUITER ROUTES ==========

// Search active students
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
        
        // Hide contact info
        const hiddenStudents = students?.map(s => ({
            id: s.id,
            full_name: s.full_name,
            current_city: s.current_city,
            current_state: s.current_state,
            university_name: s.university_name,
            visa_type: s.visa_type,
            graduation_date: s.graduation_date,
            years_of_experience: s.years_of_experience
        })) || [];
        
        res.json({
            success: true,
            count: hiddenStudents.length,
            students: hiddenStudents
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Search failed' });
    }
});

// Get recruiter stats
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
                credits: recruiter?.credits_remaining || 0,
                tier: recruiter?.subscription_tier || 'free',
                total_searches: recruiter?.total_searches || 0,
                total_contacts: recruiter?.total_contacts || 0,
                total_hires: recruiter?.total_hires || 0
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to get stats' });
    }
});

// View full student profile
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
        
        // Get skills
        const { data: skills } = await supabase
            .from('student_skills')
            .select('skills(*)')
            .eq('student_id', student.id);
        
        // Log view
        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('id')
            .eq('auth_user_id', req.user.id)
            .single();
        
        if (recruiter) {
            await supabase
                .from('view_logs')
                .insert({ recruiter_id: recruiter.id, student_id: student.id });
        }
        
        res.json({
            success: true,
            student: {
                ...student,
                skills: skills?.map(s => s.skills?.skill_name) || []
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to load student' });
    }
});

// Contact student (costs credit)
app.post('/api/recruiter/contact', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { student_id, message } = req.body;
        
        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('id, credits_remaining, company_name')
            .eq('auth_user_id', req.user.id)
            .single();
        
        if (recruiter.credits_remaining <= 0) {
            return res.status(402).json({ error: 'Insufficient credits. Please upgrade.' });
        }
        
        const { data: student } = await supabase
            .from('students')
            .select('email, full_name')
            .eq('id', student_id)
            .single();
        
        // Deduct credit
        await supabase
            .from('recruiters')
            .update({ 
                credits_remaining: recruiter.credits_remaining - 1,
                total_contacts: supabase.raw('total_contacts + 1')
            })
            .eq('id', recruiter.id);
        
        // Log contact
        await supabase
            .from('contact_logs')
            .insert({ recruiter_id: recruiter.id, student_id: student_id });
        
        console.log(`📧 Email to ${student.email}: ${message}`);
        
        res.json({ 
            success: true, 
            message: 'Student contacted successfully',
            credits_remaining: recruiter.credits_remaining - 1
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to contact student' });
    }
});

// Mark student as hired
app.post('/api/recruiter/mark-hired', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { student_id } = req.body;
        
        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('id')
            .eq('auth_user_id', req.user.id)
            .single();
        
        await supabase
            .from('students')
            .update({ 
                profile_status: 'hired',
                hired_by_recruiter_id: recruiter.id,
                hired_at: new Date(),
                is_actively_looking: false
            })
            .eq('id', student_id);
        
        await supabase
            .from('recruiters')
            .update({ total_hires: supabase.raw('total_hires + 1') })
            .eq('id', recruiter.id);
        
        res.json({ success: true, message: 'Student marked as hired' });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to mark as hired' });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
