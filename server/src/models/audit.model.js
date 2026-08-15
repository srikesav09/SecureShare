import mongoose from "mongoose";

const auditSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        },

        action: {
            type: String,
            required: true
        },

        resourceType: {
            type: String,
            default: null
        },

        resourceId: {
            type: mongoose.Schema.Types.ObjectId,
            default: null
        },

        status: {
            type: String,
            enum: ["SUCCESS", "FAILED"],
            required: true
        },
        
        requestId: {
            type: String,
            default: null
        },

        ipAddress: {
            type: String
        },

        userAgent: {
            type: String
        },

        details: {
            type: mongoose.Schema.Types.Mixed,
            default: {}
        }
    },
    {
        timestamps: true
    }
);

export default mongoose.model("Audit", auditSchema);