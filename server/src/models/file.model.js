import mongoose from 'mongoose';

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

    s3Key: {
      type: String,
      required: true,
      unique: true,
    },

    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },

    encrypted: {
      type: Boolean,
      default: true,
    },

    iv: {
      type: String,
    },

    hash: {
      type: String,
    },

    securityAnalysis: {
      status: {
        type: String,
        enum: ['CLEAN', 'REVIEW', 'QUARANTINED', 'RELEASED', 'BLOCKED'],
        default: 'CLEAN',
      },
      riskScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 0,
      },
      findings: {
        type: [
          {
            code: String,
            severity: {
              type: String,
              enum: ['LOW', 'MEDIUM', 'HIGH'],
            },
            title: String,
            detail: String,
            recommendation: String,
          },
        ],
        default: [],
      },
      checkedAt: {
        type: Date,
        default: null,
      },
      engine: {
        type: String,
        default: 'SecureShare header heuristics',
      },
      releasedAt: { type: Date, default: null },
      releasedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    },
  },
  {
    timestamps: true,
  },
);

export default mongoose.model('File', fileSchema);
