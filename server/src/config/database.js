import mongoose from "mongoose";

const connectDatabase = async()=>{
  try{
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("Connected to mongoDB atlas");
  } catch (error){
    console.error("MongoDB Connection Failed");
    console.error(error.message);

    process.exit(1);
  }
};

export default connectDatabase; 