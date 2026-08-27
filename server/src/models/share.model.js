import mongoose from "mongoose";

const shareSchema = new mongoose.Schema(
  {
    file: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "File",
      required: true,
    },

    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    token: {
      type: String,
      required: true,
      unique: true,
    },

    passwordHash: {
      type: String,
      default: null,
    },

    expiresAt: {
      type: Date,
      required: true,
    },

    isRevoked: {
      type: Boolean,
      default: false,
    },

    downloadCount: {
    type: Number,
    required: true,
    default: 0,
    min: 0,
    validate: {
        validator: Number.isInteger,
        message: "downloadCount must be a non-negative integer"
    }
  },

  maxDownloads: {
    type: Number,
    default: null,
    min: 1,
    validate: {
        validator: function (value) {
            return (
                value === null ||
                Number.isInteger(value)
            );
        },
        message: "maxDownloads must be a positive integer"
    }
  },
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("Share", shareSchema);