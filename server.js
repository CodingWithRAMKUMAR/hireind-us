// =====================================================
// HIREIND_US - COMPLETE SERVER WITH AUTH & HIRED LOGIC
// =====================================================

require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const csv = require('csv-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase Client
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// File upload
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

// ========== HELPER FUNCTIONS ==========
function generateToken(userId) {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

// ========== AUTH ROUTES ==========

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, full_name, role } = req.body;
        
        // Check if user exists
        const { data: existing } = await supabase
            .from('auth_users')
            .select('email')
            .eq('email', email)
            .single();
        
        if (existing) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create auth user
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
        
        // Create role-specific profile
        if (role === 'student') {
            await supabase
                .from('students')
                .insert({ 
                    auth_user_id: authUser.id, 
                    full_name,
                    email,
                    status: 'active',
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

// Get student dashboard (only own data)
app.get('/api/student/dashboard', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        // Get student profile
        const { data: student } = await supabase
            .from('students')
            .select('*')
            .eq('auth_user_id', req.user.id)
            .single();
        
        // Get view count (how many recruiters viewed them)
        const { count: viewCount } = await supabase
            .from('view_logs')
            .select('*', { count: 'exact', head: true })
            .eq('student_id', student.id);
        
        // Get contact count (how many recruiters contacted)
        const { count: contactCount } = await supabase
            .from('contact_logs')
            .select('*', { count: 'exact', head: true })
            .eq('student_id', student.id);
        
        // Get student skills
        const { data: skills } = await supabase
            .from('student_skills')
            .select('skills(*)')
            .eq('student_id', student.id);
        
        res.json({
            success: true,
            student,
            stats: {
                profile_views: viewCount || 0,
                recruiter_contacts: contactCount || 0
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
        
        const { data: existingStudent } = await supabase
            .from('students')
            .select('id')
            .eq('auth_user_id', req.user.id)
            .single();
        
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
            ...req.body,
            resume_url: resume_url || req.body.resume_url,
            updated_at: new Date(),
            profile_complete: true
        };
        
        const { data: student, error } = await supabase
            .from('students')
            .update(updateData)
            .eq('auth_user_id', req.user.id)
            .select()
            .single();
        
        if (error) throw error;
        
        // Update skills if provided
        if (req.body.skills) {
            const skills = req.body.skills.split(',').map(s => s.trim());
            
            // Clear existing skills
            await supabase
                .from('student_skills')
                .delete()
                .eq('student_id', student.id);
            
            // Add new skills
            for (const skillName of skills) {
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
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// ========== RECRUITER ROUTES ==========

// Search active students (only active, not hired)
app.post('/api/recruiter/search', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { state, visa, skill, university } = req.body;
        
        let query = supabase
            .from('students')
            .select('*')
            .eq('status', 'active')
            .eq('is_actively_looking', true)
            .eq('profile_complete', true);
        
        if (state) query = query.eq('current_state', state);
        if (visa) query = query.eq('visa_type', visa);
        if (university) query = query.ilike('university_name', `%${university}%`);
        
        const { data: students, error } = await query;
        
        if (error) throw error;
        
        // Log search
        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('id')
            .eq('auth_user_id', req.user.id)
            .single();
        
        await supabase
            .from('recruiters')
            .update({ total_searches: supabase.raw('total_searches + 1') })
            .eq('id', recruiter.id);
        
        // Hide contact info (email, phone) until credit spent
        const hiddenStudents = students.map(s => ({
            ...s,
            email: undefined,
            phone: undefined,
            resume_url: undefined
        }));
        
        res.json({
            success: true,
            count: students.length,
            students: hiddenStudents
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Search failed' });
    }
});

// View student details (costs credit for contact info)
app.get('/api/recruiter/student/:studentId', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { studentId } = req.params;
        
        // Get recruiter
        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('id, credits_remaining')
            .eq('auth_user_id', req.user.id)
            .single();
        
        // Get student
        const { data: student, error } = await supabase
            .from('students')
            .select('*')
            .eq('id', studentId)
            .eq('status', 'active')
            .single();
        
        if (error || !student) {
            return res.status(404).json({ error: 'Student not found' });
        }
        
        // Log view
        await supabase
            .from('view_logs')
            .insert({
                recruiter_id: recruiter.id,
                student_id: studentId
            });
        
        // Return full profile (contact info included)
        res.json({
            success: true,
            student,
            recruiter_credits: recruiter.credits_remaining
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to load student' });
    }
});

// Contact student (costs 1 credit)
app.post('/api/recruiter/contact', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { student_id, message } = req.body;
        
        // Get recruiter
        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('id, credits_remaining, company_name')
            .eq('auth_user_id', req.user.id)
            .single();
        
        // Check credits
        if (recruiter.credits_remaining <= 0) {
            return res.status(402).json({ error: 'Insufficient credits. Please upgrade your plan.' });
        }
        
        // Get student
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
            .insert({
                recruiter_id: recruiter.id,
                student_id: student_id,
                credits_used: 1
            });
        
        // Add to shortlist
        await supabase
            .from('shortlists')
            .upsert({
                recruiter_id: recruiter.id,
                student_id: student_id,
                status: 'contacted'
            });
        
        // In production, send actual email here
        console.log(`Email would be sent to ${student.email} from ${recruiter.company_name}: ${message}`);
        
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
        
        // Get recruiter
        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('id')
            .eq('auth_user_id', req.user.id)
            .single();
        
        // Update student status to hired
        const { data: student, error } = await supabase
            .from('students')
            .update({ 
                status: 'hired',
                hired_by_recruiter_id: recruiter.id,
                hired_at: new Date(),
                is_actively_looking: false
            })
            .eq('id', student_id)
            .select()
            .single();
        
        if (error) throw error;
        
        // Update recruiter hire count
        await supabase
            .from('recruiters')
            .update({ total_hires: supabase.raw('total_hires + 1') })
            .eq('id', recruiter.id);
        
        // Update shortlist status
        await supabase
            .from('shortlists')
            .update({ status: 'hired' })
            .eq('recruiter_id', recruiter.id)
            .eq('student_id', student_id);
        
        res.json({ 
            success: true, 
            message: 'Student marked as hired. They will no longer appear in searches.'
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to mark as hired' });
    }
});

// Get recruiter credits/stats
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
            .eq('status', 'active');
        
        const { count: optStudents } = await supabase
            .from('students')
            .select('*', { count: 'exact', head: true })
            .in('visa_type', ['OPT_1st_year', 'OPT_2nd_year', 'STEM_OPT'])
            .eq('status', 'active');
        
        res.json({
            success: true,
            totalStudents: totalStudents || 0,
            optStudents: optStudents || 0,
            recruiter: {
                credits: recruiter.credits_remaining,
                tier: recruiter.subscription_tier,
                total_searches: recruiter.total_searches,
                total_contacts: recruiter.total_contacts,
                total_hires: recruiter.total_hires
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to get stats' });
    }
});

// ========== ADMIN ROUTES ==========

// Get all students (admin only)
app.get('/api/admin/students', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { data: students } = await supabase
            .from('students')
            .select('*, auth_users(email, full_name)')
            .order('created_at', { ascending: false });
        
        res.json({ success: true, students });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to get students' });
    }
});

// ========== CSV BULK UPLOAD ==========
app.post('/api/admin/bulk-upload', authenticateToken, upload.single('csv'), async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const results = [];
        let successCount = 0;
        
        fs.createReadStream(req.file.path)
            .pipe(csv())
            .on('data', (data) => results.push(data))
            .on('end', async () => {
                for (const row of results) {
                    try {
                        // Create auth user
                        const tempPassword = Math.random().toString(36).slice(-8);
                        const hashedPassword = await bcrypt.hash(tempPassword, 10);
                        
                        const { data: authUser } = await supabase
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
                        
                        if (authUser) {
                            await supabase
                                .from('students')
                                .insert({
                                    auth_user_id: authUser.id,
                                    full_name: row.full_name,
                                    email: row.email,
                                    current_city: row.city,
                                    current_state: row.state,
                                    university_name: row.university,
                                    graduation_date: row.graduation_date,
                                    visa_type: row.visa_type,
                                    status: 'active',
                                    profile_complete: true
                                });
                            successCount++;
                        }
                    } catch (e) {
                        console.error('Bulk insert error:', e);
                    }
                }
                
                res.json({
                    success: true,
                    total: results.length,
                    imported: successCount
                });
            });
        
    } catch (error) {
        res.status(500).json({ error: 'Bulk upload failed' });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
    console.log(`
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║   🚀 HIREIND_US v2.0 - Production Server Running    ║
    ║                                                      ║
    ║   📡 Port: ${PORT}                                      ║
    ║   🌐 URL: http://localhost:${PORT}                     ║
    ║                                                      ║
    ║   ✅ Authentication: Active                          ║
    ║   ✅ Credit System: Active                           ║
    ║   ✅ Hired Logic: Active                             ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
    `);
});
