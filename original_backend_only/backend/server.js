const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

/* -------------------- DB CONNECT -------------------- */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.log('MongoDB error:', err));

/* -------------------- SCHEMAS -------------------- */
const userSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },

    role: {
      type: String,
      enum: ['patient', 'doctor', 'pharmacy'],
      required: true
    },

    phone: String,
    city: String,
    state: String,

    // patient fields
    age: Number,
    gender: String,
    bloodGroup: String,
    allergies: String,
    medicalHistory: String,

    // doctor fields
    specialization: String,
    experience: String,
    hospitalName: String,
    consultationFee: Number,
    availableDays: [String],
    availableTime: String,
    about: String,
    isApproved: { type: Boolean, default: true },

    // pharmacy fields
    pharmacyName: String,
    address: String,
    licenseNumber: String,

    profileImage: String
  },
  { timestamps: true }
);

const appointmentSchema = new mongoose.Schema(
  {
    patientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },

    patientName: String,
    doctorName: String,

    city: String,
    state: String,

    appointmentDate: String,
    appointmentTime: String,
    issue: String,
    notes: String,

    status: {
      type: String,
      enum: ['pending', 'accepted', 'rejected', 'completed', 'cancelled'],
      default: 'pending'
    }
  },
  { timestamps: true }
);

const prescriptionSchema = new mongoose.Schema(
  {
    appointmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Appointment' },
    patientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },

    patientName: String,
    doctorName: String,

    diagnosis: String,
    medicines: [
      {
        name: String,
        dosage: String,
        frequency: String,
        days: String
      }
    ],
    advice: String
  },
  { timestamps: true }
);

const orderSchema = new mongoose.Schema(
  {
    patientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    pharmacyId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },

    patientName: String,
    pharmacyName: String,

    city: String,
    state: String,

    orderType: {
      type: String,
      enum: ['medicine_order', 'advance_booking'],
      default: 'medicine_order'
    },

    items: [
      {
        name: String,
        quantity: Number
      }
    ],

    prescriptionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Prescription', default: null },

    status: {
      type: String,
      enum: ['placed', 'confirmed', 'packed', 'out_for_delivery', 'delivered', 'cancelled'],
      default: 'placed'
    }
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);
const Appointment = mongoose.model('Appointment', appointmentSchema);
const Prescription = mongoose.model('Prescription', prescriptionSchema);
const Order = mongoose.model('Order', orderSchema);

/* -------------------- AUTH MIDDLEWARE -------------------- */
const auth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id).select('-password');
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

const allowRoles = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied' });
    }
    next();
  };
};

/* -------------------- HELPERS -------------------- */
const createToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
};

const getLocationSortedDoctors = async (city, state) => {
  let doctors = [];

  doctors = await User.find({
    role: 'doctor',
    isApproved: true,
    city: city
  }).select('-password');

  if (doctors.length > 0) return doctors;

  doctors = await User.find({
    role: 'doctor',
    isApproved: true,
    state: state
  }).select('-password');

  if (doctors.length > 0) return doctors;

  doctors = await User.find({
    role: 'doctor',
    isApproved: true,
    city: 'New Delhi'
  }).select('-password');

  return doctors;
};

const getLocationSortedPharmacies = async (city, state) => {
  let pharmacies = [];

  pharmacies = await User.find({
    role: 'pharmacy',
    city: city
  }).select('-password');

  if (pharmacies.length > 0) return pharmacies;

  pharmacies = await User.find({
    role: 'pharmacy',
    state: state
  }).select('-password');

  if (pharmacies.length > 0) return pharmacies;

  pharmacies = await User.find({
    role: 'pharmacy',
    city: 'New Delhi'
  }).select('-password');

  return pharmacies;
};

/* -------------------- ROOT -------------------- */
app.get('/', (req, res) => {
  res.json({ message: 'PranaSetu backend running' });
});

/* -------------------- AUTH ROUTES -------------------- */

// REGISTER
app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      fullName,
      email,
      password,
      role,
      phone,
      city,
      state,
      age,
      gender,
      bloodGroup,
      allergies,
      medicalHistory,
      specialization,
      experience,
      hospitalName,
      consultationFee,
      availableDays,
      availableTime,
      about,
      pharmacyName,
      address,
      licenseNumber
    } = req.body;

    if (!fullName || !email || !password || !role) {
      return res.status(400).json({ message: 'Required fields missing' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      fullName,
      email,
      password: hashedPassword,
      role,
      phone,
      city,
      state,
      age,
      gender,
      bloodGroup,
      allergies,
      medicalHistory,
      specialization,
      experience,
      hospitalName,
      consultationFee,
      availableDays,
      availableTime,
      about,
      pharmacyName,
      address,
      licenseNumber
    });

    await user.save();

    const token = createToken(user._id);

    res.status(201).json({
      message: 'Registration successful',
      token,
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        role: user.role,
        city: user.city,
        state: user.state,
        specialization: user.specialization,
        pharmacyName: user.pharmacyName
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Register error', error: error.message });
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    if (role && user.role !== role) {
      return res.status(400).json({ message: `This account belongs to ${user.role}` });
    }

    const token = createToken(user._id);

    res.json({
      message: 'Login successful',
      token,
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        role: user.role,
        city: user.city,
        state: user.state,
        specialization: user.specialization,
        pharmacyName: user.pharmacyName
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Login error', error: error.message });
  }
});

// GET CURRENT USER
app.get('/api/auth/me', auth, async (req, res) => {
  res.json(req.user);
});

/* -------------------- PATIENT ROUTES -------------------- */

// get doctors according to patient location
app.get('/api/patient/doctors', auth, allowRoles('patient'), async (req, res) => {
  try {
    const doctors = await getLocationSortedDoctors(req.user.city, req.user.state);
    res.json(doctors);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching doctors', error: error.message });
  }
});

// get pharmacies according to patient location
app.get('/api/patient/pharmacies', auth, allowRoles('patient'), async (req, res) => {
  try {
    const pharmacies = await getLocationSortedPharmacies(req.user.city, req.user.state);
    res.json(pharmacies);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching pharmacies', error: error.message });
  }
});

// patient books appointment
app.post('/api/patient/book-appointment', auth, allowRoles('patient'), async (req, res) => {
  try {
    const { doctorId, appointmentDate, appointmentTime, issue, notes } = req.body;

    const doctor = await User.findById(doctorId);
    if (!doctor || doctor.role !== 'doctor') {
      return res.status(404).json({ message: 'Doctor not found' });
    }

    const appointment = new Appointment({
      patientId: req.user._id,
      doctorId: doctor._id,
      patientName: req.user.fullName,
      doctorName: doctor.fullName,
      city: req.user.city,
      state: req.user.state,
      appointmentDate,
      appointmentTime,
      issue,
      notes
    });

    await appointment.save();

    res.status(201).json({
      message: 'Appointment booked successfully',
      appointment
    });
  } catch (error) {
    res.status(500).json({ message: 'Booking error', error: error.message });
  }
});

// patient appointments
app.get('/api/patient/appointments', auth, allowRoles('patient'), async (req, res) => {
  try {
    const appointments = await Appointment.find({ patientId: req.user._id })
      .sort({ createdAt: -1 });

    res.json(appointments);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching appointments', error: error.message });
  }
});

// patient prescriptions
app.get('/api/patient/prescriptions', auth, allowRoles('patient'), async (req, res) => {
  try {
    const prescriptions = await Prescription.find({ patientId: req.user._id })
      .sort({ createdAt: -1 });

    res.json(prescriptions);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching prescriptions', error: error.message });
  }
});

// patient places medicine order / advance booking
app.post('/api/patient/place-order', auth, allowRoles('patient'), async (req, res) => {
  try {
    const { pharmacyId, items, orderType, prescriptionId } = req.body;

    const pharmacy = await User.findById(pharmacyId);
    if (!pharmacy || pharmacy.role !== 'pharmacy') {
      return res.status(404).json({ message: 'Pharmacy not found' });
    }

    const order = new Order({
      patientId: req.user._id,
      pharmacyId: pharmacy._id,
      patientName: req.user.fullName,
      pharmacyName: pharmacy.pharmacyName || pharmacy.fullName,
      city: req.user.city,
      state: req.user.state,
      items,
      orderType,
      prescriptionId: prescriptionId || null
    });

    await order.save();

    res.status(201).json({
      message: 'Order placed successfully',
      order
    });
  } catch (error) {
    res.status(500).json({ message: 'Order error', error: error.message });
  }
});

// patient order history
app.get('/api/patient/orders', auth, allowRoles('patient'), async (req, res) => {
  try {
    const orders = await Order.find({ patientId: req.user._id })
      .sort({ createdAt: -1 });

    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching orders', error: error.message });
  }
});

/* -------------------- DOCTOR ROUTES -------------------- */

// doctor dashboard appointments
app.get('/api/doctor/appointments', auth, allowRoles('doctor'), async (req, res) => {
  try {
    const appointments = await Appointment.find({ doctorId: req.user._id })
      .sort({ createdAt: -1 });

    res.json(appointments);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching doctor appointments', error: error.message });
  }
});

// doctor accepts/rejects/completes appointment
app.patch('/api/doctor/appointments/:id/status', auth, allowRoles('doctor'), async (req, res) => {
  try {
    const { status } = req.body;

    const validStatuses = ['accepted', 'rejected', 'completed', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    const appointment = await Appointment.findOne({
      _id: req.params.id,
      doctorId: req.user._id
    });

    if (!appointment) {
      return res.status(404).json({ message: 'Appointment not found' });
    }

    appointment.status = status;
    await appointment.save();

    res.json({
      message: 'Appointment status updated',
      appointment
    });
  } catch (error) {
    res.status(500).json({ message: 'Status update error', error: error.message });
  }
});

// doctor creates prescription
app.post('/api/doctor/prescription', auth, allowRoles('doctor'), async (req, res) => {
  try {
    const { appointmentId, patientId, diagnosis, medicines, advice } = req.body;

    const patient = await User.findById(patientId);
    if (!patient || patient.role !== 'patient') {
      return res.status(404).json({ message: 'Patient not found' });
    }

    const prescription = new Prescription({
      appointmentId,
      patientId,
      doctorId: req.user._id,
      patientName: patient.fullName,
      doctorName: req.user.fullName,
      diagnosis,
      medicines,
      advice
    });

    await prescription.save();

    res.status(201).json({
      message: 'Prescription created successfully',
      prescription
    });
  } catch (error) {
    res.status(500).json({ message: 'Prescription error', error: error.message });
  }
});

// doctor own profile
app.get('/api/doctor/profile', auth, allowRoles('doctor'), async (req, res) => {
  res.json(req.user);
});

/* -------------------- PHARMACY ROUTES -------------------- */

// pharmacy gets all incoming orders
app.get('/api/pharmacy/orders', auth, allowRoles('pharmacy'), async (req, res) => {
  try {
    const orders = await Order.find({ pharmacyId: req.user._id })
      .sort({ createdAt: -1 });

    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching pharmacy orders', error: error.message });
  }
});

// pharmacy updates order status
app.patch('/api/pharmacy/orders/:id/status', auth, allowRoles('pharmacy'), async (req, res) => {
  try {
    const { status } = req.body;

    const validStatuses = ['confirmed', 'packed', 'out_for_delivery', 'delivered', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    const order = await Order.findOne({
      _id: req.params.id,
      pharmacyId: req.user._id
    });

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    order.status = status;
    await order.save();

    res.json({
      message: 'Order status updated',
      order
    });
  } catch (error) {
    res.status(500).json({ message: 'Order status update error', error: error.message });
  }
});

// pharmacy profile
app.get('/api/pharmacy/profile', auth, allowRoles('pharmacy'), async (req, res) => {
  res.json(req.user);
});

/* -------------------- COMMON SEARCH ROUTES -------------------- */

// public doctors list for frontend if needed
app.get('/api/public/doctors', async (req, res) => {
  try {
    const doctors = await User.find({
      role: 'doctor',
      isApproved: true
    }).select('-password');

    res.json(doctors);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching doctors', error: error.message });
  }
});

// public pharmacies list for frontend if needed
app.get('/api/public/pharmacies', async (req, res) => {
  try {
    const pharmacies = await User.find({
      role: 'pharmacy'
    }).select('-password');

    res.json(pharmacies);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching pharmacies', error: error.message });
  }
});

/* -------------------- UPDATE PROFILE -------------------- */
app.put('/api/profile/update', auth, async (req, res) => {
  try {
    const updates = { ...req.body };
    delete updates.password;
    delete updates.email;
    delete updates.role;

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      { new: true }
    ).select('-password');

    res.json({
      message: 'Profile updated successfully',
      user: updatedUser
    });
  } catch (error) {
    res.status(500).json({ message: 'Profile update error', error: error.message });
  }
});

/* -------------------- SERVER -------------------- */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});