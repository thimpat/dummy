const authRoutes = require('./auth');
const homeRoutes = require('./home');

const router = express.Router();

router.use('/auth', authRoutes);
router.get('/', (req, res) => {
  res.json({ message: 'Welcome to the API' });
});

module.exports = router;