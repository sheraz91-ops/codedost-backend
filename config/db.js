require('dotenv').config();
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    console.log('\n🔄 Connecting to MongoDB...');
    console.log('   URI check:', process.env.MONGODB_URI ? '✅ Found' : '❌ MISSING - check .env file');

    const conn = await mongoose.connect(process.env.MONGODB_URI);

    console.log(`✅ MongoDB Connected Successfully!`);
    console.log(`   Host: ${conn.connection.host}`);
    console.log(`   Database: ${conn.connection.name}\n`);

    return conn;
  } catch (error) {
    console.error(`\n❌ MongoDB Connection Error: ${error.message}\n`);
    process.exit(1);
  }
};

module.exports = connectDB;