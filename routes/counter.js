const express = require('express');
const router = express.Router();
const Counter = require('../models/Counter');

const getCounterDocument = async () => {
  let counter = await Counter.findOne();
  if (!counter) {
    counter = await Counter.create({ value: 0 });
  }
  return counter;
};

router.get('/', async (req, res) => {
  try {
    const counter = await getCounterDocument();
    res.json({ success: true, counter: counter.value });
  } catch (error) {
    console.error('GET /counter error:', error);
    res.status(500).json({ success: false, message: 'Unable to read counter' });
  }
});

router.post('/', async (req, res) => {
  try {
    const counter = await Counter.findOneAndUpdate(
      {},
      { $inc: { value: 1 } },
      { new: true, upsert: true }
    );
    res.json({ success: true, counter: counter.value });
  } catch (error) {
    console.error('POST /counter error:', error);
    res.status(500).json({ success: false, message: 'Unable to update counter' });
  }
});

module.exports = router;