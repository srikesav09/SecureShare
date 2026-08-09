import mongoose from "mongoose";

const fileSchema = new mongoose.Schema(
  {
    originalName: {
      type: String,
      required: true,
      trim: true,
    },

    storedName: {
      type: String,
      required: true,
      unique: true,
    },

    mimeType: {
      type: String,
      required: true,
    },

    size: {
      type: Number,
      required: true,
    },

    path: {
      type: String,
      required: true,
    },

    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    encrypted: {
      type: Boolean,
      default: true
    },

    iv: {
        type: String
    },

    hash: {
        type: String
    }
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("File", fileSchema);