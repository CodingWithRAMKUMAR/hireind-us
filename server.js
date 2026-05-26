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

// Supabase Client (Regular - for most operations)
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// Supabase Admin Client (Service Role - for storage uploads)
const supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
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

// ========== MULTER CONFIGURATION (FIXED - Using memoryStorage) ==========
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage, 
    limits: { fileSize: 10 * 1024 * 1024 }  // 10MB limit
});

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
                    is_actively_looking: true,
                    profile_complete: false,
                    source: 'manual',
                    profile_view_count: 0
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
        console.error('Register error:', error);
        res.status(500).json({ error: 'Registration failed: ' + error.message });
    }
});

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
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

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
                    source: 'manual',
                    profile_view_count: 0
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
        
        const { count: unreadCount } = await supabase
            .from('notifications')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.user.id)
            .eq('is_read', false);
        
        const { count: unreadMessages } = await supabase
            .from('contact_logs')
            .select('*', { count: 'exact', head: true })
            .eq('student_id', student.id)
            .eq('is_read', false);
        
        res.json({
            success: true,
            student,
            stats: {
                profile_views: student.profile_view_count || 0,
                recruiter_contacts: 0,
                unread_notifications: unreadCount || 0,
                unread_messages: unreadMessages || 0
            },
            skills: skills?.map(s => s.skills) || [],
            resumes: resumes || []
        });
        
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to load dashboard: ' + error.message });
    }
});

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
                    source: 'manual',
                    profile_view_count: 0
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
            const fileBuffer = req.file.buffer;
            
            if (fileBuffer.length === 0) {
                return res.status(400).json({ error: 'Uploaded file is empty' });
            }
            
            const cleanFileName = req.file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
            const fileName = `${Date.now()}_${req.user.id}_${cleanFileName}`;
            
            const { error: uploadError } = await supabaseAdmin.storage
                .from('resumes')
                .upload(fileName, fileBuffer, {
                    contentType: req.file.mimetype || 'application/pdf',
                    cacheControl: '3600'
                });
            
            if (!uploadError) {
                const { data: urlData } = supabase.storage
                    .from('resumes')
                    .getPublicUrl(fileName);
                resume_url = urlData.publicUrl;
                
                await supabase
                    .from('resume_versions')
                    .insert({
                        student_id: existingStudent.id,
                        resume_url: resume_url,
                        file_name: req.file.originalname,
                        is_active: true
                    });
                
                await supabase
                    .from('resume_versions')
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
                    if (newSkill && newSkill.length > 0) skill = newSkill[0];
                }
                
                if (skill) {
                    await supabase
                        .from('student_skills')
                        .insert({ student_id: student.id, skill_id: skill.id });
                }
            }
        }
        
        res.json({ success: true, student, message: 'Profile updated successfully' });
        
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile: ' + error.message });
    }
});

// ========== RESUME UPLOAD ROUTE (FIXED - Proper file handling) ==========
app.post('/api/student/upload-resume', authenticateToken, upload.single('resume'), async (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        console.log('📄 Upload request from user:', req.user.id);
        
        // Get student record
        const { data: student, error: studentError } = await supabase
            .from('students')
            .select('id')
            .eq('auth_user_id', req.user.id)
            .single();
        
        if (studentError || !student) {
            console.error('Student fetch error:', studentError);
            return res.status(404).json({ error: 'Student profile not found. Please complete your profile first.' });
        }
        
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        const fileBuffer = req.file.buffer;
        
        console.log('File name:', req.file.originalname);
        console.log('File size:', fileBuffer.length, 'bytes');
        console.log('File mimetype:', req.file.mimetype);
        
        if (fileBuffer.length === 0) {
            return res.status(400).json({ error: 'File is empty. Please select a valid PDF file.' });
        }
        
        if (req.file.mimetype !== 'application/pdf') {
            return res.status(400).json({ error: 'Only PDF files are allowed.' });
        }
        
        // Clean filename
        const cleanFileName = req.file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
        const fileName = `${Date.now()}_${req.user.id}_${cleanFileName}`;
        
        // Upload to Supabase Storage using Admin client
        const { data: uploadData, error: uploadError } = await supabaseAdmin.storage
            .from('resumes')
            .upload(fileName, fileBuffer, {
                contentType: 'application/pdf',
                cacheControl: '3600'
            });
        
        if (uploadError) {
            console.error('Storage upload error:', uploadError);
            return res.status(500).json({ error: 'Storage upload failed: ' + uploadError.message });
        }
        
        console.log('Upload successful! File size in storage:', uploadData?.size);
        
        // Get public URL
        const { data: urlData } = supabase.storage
            .from('resumes')
            .getPublicUrl(fileName);
        
        const resume_url = urlData.publicUrl;
        
        // Set all existing resumes to inactive
        await supabase
            .from('resume_versions')
            .update({ is_active: false })
            .eq('student_id', student.id);
        
        // Save to database
        const { data: resume, error: insertError } = await supabase
            .from('resume_versions')
            .insert({
                student_id: student.id,
                resume_url: resume_url,
                file_name: req.file.originalname,
                is_active: true,
                uploaded_at: new Date().toISOString()
            })
            .select()
            .single();
        
        if (insertError) {
            console.error('Database insert error:', insertError);
            return res.status(500).json({ error: 'Failed to save resume record: ' + insertError.message });
        }
        
        console.log('✅ Resume saved to database, ID:', resume.id);
        
        res.json({ 
            success: true, 
            resume, 
            message: 'Resume uploaded successfully',
            file_size: fileBuffer.length
        });
        
    } catch (error) {
        console.error('Upload resume error:', error);
        res.status(500).json({ error: 'Failed to upload resume: ' + error.message });
    }
});

// ========== STUDENT INBOX ROUTES ==========

app.get('/api/student/messages', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { data: student } = await supabase
            .from('students')
            .select('id')
            .eq('auth_user_id', req.user.id)
            .single();
        
        if (!student) {
            return res.status(404).json({ error: 'Student profile not found' });
        }
        
        const { data: messages, error } = await supabase
            .from('contact_logs')
            .select(`
                id,
                message,
                subject,
                contacted_at,
                is_read,
                recruiter_id,
                recruiters (
                    id,
                    company_name
                )
            `)
            .eq('student_id', student.id)
            .order('contacted_at', { ascending: false });
        
        if (error) throw error;
        
        res.json({ success: true, messages: messages || [] });
        
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ error: 'Failed to get messages' });
    }
});

app.post('/api/student/mark-read', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { message_id } = req.body;
        
        const { data: student } = await supabase
            .from('students')
            .select('id')
            .eq('auth_user_id', req.user.id)
            .single();
        
        if (!student) {
            return res.status(404).json({ error: 'Student profile not found' });
        }
        
        await supabase
            .from('contact_logs')
            .update({ is_read: true })
            .eq('id', message_id)
            .eq('student_id', student.id);
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Mark read error:', error);
        res.status(500).json({ error: 'Failed to mark as read' });
    }
});

app.post('/api/student/reply', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { original_message_id, message, subject } = req.body;
        
        if (!original_message_id || !message) {
            return res.status(400).json({ error: 'Original message ID and reply message are required' });
        }
        
        const { data: originalMessage, error: msgError } = await supabase
            .from('contact_logs')
            .select('recruiter_id, subject')
            .eq('id', original_message_id)
            .single();
        
        if (msgError || !originalMessage) {
            return res.status(404).json({ error: 'Original message not found' });
        }
        
        const { data: student } = await supabase
            .from('students')
            .select('id, full_name, email')
            .eq('auth_user_id', req.user.id)
            .single();
        
        if (!student) {
            return res.status(404).json({ error: 'Student profile not found' });
        }
        
        const { data: reply, error: replyError } = await supabase
            .from('contact_logs')
            .insert({
                student_id: student.id,
                recruiter_id: originalMessage.recruiter_id,
                message: message,
                subject: subject || `RE: ${originalMessage.subject}`,
                contacted_at: new Date().toISOString(),
                reply_to_id: original_message_id,
                is_read: false
            })
            .select()
            .single();
        
        if (replyError) {
            console.error('Reply error:', replyError);
            return res.status(500).json({ error: 'Failed to send reply' });
        }
        
        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('auth_user_id')
            .eq('id', originalMessage.recruiter_id)
            .single();
        
        if (recruiter && recruiter.auth_user_id) {
            await supabase
                .from('notifications')
                .insert({
                    user_id: recruiter.auth_user_id,
                    type: 'reply',
                    title: 'Student Reply: ' + student.full_name,
                    message: message.substring(0, 100) + (message.length > 100 ? '...' : ''),
                    related_id: reply.id,
                    is_read: false
                });
        }
        
        res.json({ success: true, message: 'Reply sent successfully' });
        
    } catch (error) {
        console.error('Reply error:', error);
        res.status(500).json({ error: 'Failed to send reply' });
    }
});

// ========== RECRUITER INBOX ROUTES ==========

app.get('/api/recruiter/messages', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { data: recruiter, error: recruiterError } = await supabase
            .from('recruiters')
            .select('id, company_name')
            .eq('auth_user_id', req.user.id)
            .single();
        
        if (recruiterError || !recruiter) {
            return res.status(404).json({ error: 'Recruiter profile not found' });
        }
        
        const { data: messages, error } = await supabase
            .from('contact_logs')
            .select(`
                id,
                message,
                subject,
                contacted_at,
                is_read,
                student_id,
                reply_to_id,
                students (
                    id,
                    full_name,
                    email,
                    university_name,
                    current_city,
                    current_state
                )
            `)
            .eq('recruiter_id', recruiter.id)
            .order('contacted_at', { ascending: false });
        
        if (error) throw error;
        
        res.json({ 
            success: true, 
            messages: messages || [],
            company_name: recruiter.company_name
        });
        
    } catch (error) {
        console.error('Get recruiter messages error:', error);
        res.status(500).json({ error: 'Failed to get messages' });
    }
});

app.post('/api/recruiter/mark-read', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { message_id } = req.body;
        
        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('id')
            .eq('auth_user_id', req.user.id)
            .single();
        
        if (!recruiter) {
            return res.status(404).json({ error: 'Recruiter not found' });
        }
        
        await supabase
            .from('contact_logs')
            .update({ is_read: true })
            .eq('id', message_id)
            .eq('recruiter_id', recruiter.id);
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Mark read error:', error);
        res.status(500).json({ error: 'Failed to mark as read' });
    }
});

app.get('/api/recruiter/unread-count', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('id')
            .eq('auth_user_id', req.user.id)
            .single();
        
        if (!recruiter) {
            return res.json({ success: true, count: 0 });
        }
        
        const { count } = await supabase
            .from('contact_logs')
            .select('*', { count: 'exact', head: true })
            .eq('recruiter_id', recruiter.id)
            .eq('is_read', false);
        
        res.json({ success: true, count: count || 0 });
        
    } catch (error) {
        res.json({ success: true, count: 0 });
    }
});

// ========== NOTIFICATION ROUTES ==========

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
        console.error('Notifications error:', error);
        res.json({ success: true, notifications: [] });
    }
});

app.post('/api/notifications/mark-read', authenticateToken, async (req, res) => {
    try {
        const { notification_id } = req.body;
        
        await supabase
            .from('notifications')
            .update({ is_read: true })
            .eq('id', notification_id)
            .eq('user_id', req.user.id);
        
        res.json({ success: true });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to mark notification' });
    }
});

app.get('/api/notifications/unread-count', authenticateToken, async (req, res) => {
    try {
        const { count } = await supabase
            .from('notifications')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.user.id)
            .eq('is_read', false);
        
        res.json({ success: true, count: count || 0 });
        
    } catch (error) {
        res.json({ success: true, count: 0 });
    }
});

// ========== RECRUITER ROUTES ==========

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
        
        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('id')
            .eq('auth_user_id', req.user.id)
            .single();
        
        if (recruiter) {
            await supabase.from('view_logs').insert({ recruiter_id: recruiter.id, student_id: student.id });
        }
        
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

app.post('/api/recruiter/contact', authenticateToken, async (req, res) => {
    try {
        console.log('📞 Contact request received');
        
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied - Not a recruiter' });
        }
        
        const { student_id, message, subject } = req.body;
        
        if (!student_id) {
            return res.status(400).json({ error: 'Student ID is required' });
        }
        
        const { data: recruiter, error: recruiterError } = await supabase
            .from('recruiters')
            .select('id, credits_remaining, company_name, total_contacts')
            .eq('auth_user_id', req.user.id)
            .single();
        
        if (recruiterError) {
            console.error('Recruiter fetch error:', recruiterError);
            return res.status(500).json({ error: 'Recruiter profile not found' });
        }
        
        if (!recruiter || recruiter.credits_remaining <= 0) {
            return res.status(402).json({ error: 'Insufficient credits. Please upgrade your plan.' });
        }
        
        const { data: student, error: studentError } = await supabase
            .from('students')
            .select('id, email, full_name, auth_user_id')
            .eq('id', student_id)
            .single();
        
        if (studentError || !student) {
            console.error('Student fetch error:', studentError);
            return res.status(404).json({ error: 'Student not found' });
        }
        
        console.log('Student found:', student.id, student.email, 'auth_user_id:', student.auth_user_id);
        
        const { error: updateError } = await supabase
            .from('recruiters')
            .update({
                credits_remaining: recruiter.credits_remaining - 1,
                total_contacts: (recruiter.total_contacts || 0) + 1
            })
            .eq('id', recruiter.id);
        
        if (updateError) {
            console.error('Credit deduction error:', updateError);
        }
        
        const { data: contact, error: contactError } = await supabase
            .from('contact_logs')
            .insert({
                recruiter_id: recruiter.id,
                student_id: student_id,
                message: message,
                subject: subject || 'Job Opportunity from ' + recruiter.company_name,
                contacted_at: new Date().toISOString(),
                is_read: false
            })
            .select()
            .single();
        
        if (contactError) {
            console.error('Contact log error:', contactError);
        } else {
            console.log('Contact logged successfully, ID:', contact.id);
        }
        
        if (student.auth_user_id) {
            try {
                await supabase
                    .from('notifications')
                    .insert({
                        user_id: student.auth_user_id,
                        type: 'contact',
                        title: 'New Message from ' + recruiter.company_name,
                        message: message.substring(0, 100) + (message.length > 100 ? '...' : ''),
                        related_id: contact?.id,
                        is_read: false
                    });
                console.log('Notification sent to student');
            } catch (notifyError) {
                console.error('Notification error:', notifyError);
            }
        }
        
        console.log(`✅ Contact successful to ${student.email} from ${recruiter.company_name}`);
        
        res.json({
            success: true,
            message: 'Student contacted successfully! They will receive your message.',
            credits_remaining: recruiter.credits_remaining - 1,
            contact_id: contact?.id
        });
        
    } catch (error) {
        console.error('❌ Contact error:', error);
        res.status(500).json({ error: 'Failed to contact student: ' + error.message });
    }
});

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
        
        if (recruiter) {
            await supabase
                .from('recruiters')
                .update({ total_hires: (recruiter.total_hires || 0) + 1 })
                .eq('id', recruiter.id);
        }
        
        res.json({ success: true, message: 'Student marked as hired' });
        
    } catch (error) {
        console.error('Mark hired error:', error);
        res.status(500).json({ error: 'Failed to mark as hired' });
    }
});

app.post('/api/recruiter/schedule-interview', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'recruiter') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const { student_id, scheduled_at, duration_minutes, interview_type, meeting_link } = req.body;
        
        const { data: recruiter } = await supabase
            .from('recruiters')
            .select('id')
            .eq('auth_user_id', req.user.id)
            .single();
        
        const { data: student } = await supabase
            .from('students')
            .select('auth_user_id')
            .eq('id', student_id)
            .single();
        
        const { data: interview, error } = await supabase
            .from('interviews')
            .insert({
                recruiter_id: recruiter.id,
                student_id: student_id,
                scheduled_at: scheduled_at,
                duration_minutes: duration_minutes || 60,
                interview_type: interview_type || 'video',
                meeting_link: meeting_link,
                status: 'scheduled'
            })
            .select()
            .single();
        
        if (error) throw error;
        
        await supabase.from('notifications').insert({
            user_id: student.auth_user_id,
            type: 'interview',
            title: 'Interview Scheduled',
            message: `An interview has been scheduled for ${new Date(scheduled_at).toLocaleString()}. Meeting link: ${meeting_link}`
        });
        
        res.json({ success: true, interview, message: 'Interview scheduled successfully' });
        
    } catch (error) {
        console.error('Schedule interview error:', error);
        res.status(500).json({ error: 'Failed to schedule interview' });
    }
});

// ========== ADMIN ROUTES ==========

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

app.post('/api/admin/bulk-upload', authenticateToken, upload.single('csv'), async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        if (!req.file) {
            return res.status(400).json({ error: 'CSV file required' });
        }
        
        const csv = require('csv-parser');
        const results = [];
        let added = 0;
        let duplicates = 0;
        
        // Create a temporary file from buffer
        const tempFilePath = path.join(__dirname, 'uploads', Date.now() + '.csv');
        fs.writeFileSync(tempFilePath, req.file.buffer);
        
        fs.createReadStream(tempFilePath)
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
                        profile_complete: true,
                        profile_view_count: 0
                    });
                    
                    added++;
                }
                
                // Clean up temp file
                fs.unlinkSync(tempFilePath);
                
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

// ========== DOWNLOAD RESUME (FIXED) ==========
app.get('/api/download-resume/:resumeId', authenticateToken, async (req, res) => {
    try {
        const { resumeId } = req.params;
        
        console.log('📄 Download resume request for ID:', resumeId);
        console.log('User role:', req.user.role);
        
        // Get resume details
        const { data: resume, error: resumeError } = await supabase
            .from('resume_versions')
            .select('*')
            .eq('id', resumeId)
            .single();
        
        if (resumeError || !resume) {
            console.error('Resume not found:', resumeError);
            return res.status(404).json({ error: 'Resume not found' });
        }
        
        console.log('Resume found for student_id:', resume.student_id);
        console.log('Resume URL:', resume.resume_url);
        
        // For recruiters, check if they have contacted this student
        if (req.user.role === 'recruiter') {
            // Get recruiter ID
            const { data: recruiter, error: recruiterError } = await supabase
                .from('recruiters')
                .select('id')
                .eq('auth_user_id', req.user.id)
                .single();
            
            if (recruiterError || !recruiter) {
                console.error('Recruiter not found:', recruiterError);
                return res.status(403).json({ error: 'Recruiter profile not found' });
            }
            
            console.log('Recruiter ID:', recruiter.id);
            
            // Check if this recruiter has contacted this student
            const { data: contact, error: contactError } = await supabase
                .from('contact_logs')
                .select('id, contacted_at')
                .eq('recruiter_id', recruiter.id)
                .eq('student_id', resume.student_id)
                .order('contacted_at', { ascending: false })
                .limit(1);
            
            console.log('Contact check result:', contact);
            
            if (!contact || contact.length === 0) {
                console.log('No contact found - access denied');
                return res.status(403).json({ error: 'You must contact the student first to download resume' });
            }
            
            console.log('Contact found - access granted');
        }
        
        // Return the download URL
        res.json({ success: true, download_url: resume.resume_url });
        
    } catch (error) {
        console.error('Download resume error:', error);
        res.status(500).json({ error: 'Failed to get resume: ' + error.message });
    }
});

// ========== HEALTH CHECK ==========

app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// ========== START SERVER ==========

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`✅ Profile view counter: ENABLED`);
    console.log(`✅ Multiple resumes: ENABLED`);
    console.log(`✅ Interview scheduling: ENABLED`);
    console.log(`✅ Notifications: ENABLED`);
    console.log(`✅ Student Inbox: ENABLED`);
    console.log(`✅ Student Reply: ENABLED`);
    console.log(`✅ Recruiter Inbox: ENABLED`);
    console.log(`✅ Recruiter Resume Download: FIXED`);
    console.log(`✅ Resume Upload: FIXED (memoryStorage)`);
});
