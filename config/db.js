const mongoose = require('mongoose');

  const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    mongoose.set("strictPopulate", false);
    
    console.log(
      `MongoDB Connected: ${conn.connection.host}`.cyan.underline.bold
    );
  } catch (err) {
    console.error(`Mongo Error: ${err.message}`.red.bold);
    process.exit(1); 
  }
};

module.exports = connectDB;