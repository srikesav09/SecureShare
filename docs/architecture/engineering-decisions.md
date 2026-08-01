# Engineering Decisions

## ED-001

### Decision
Separate frontend and backend into independent applications.

### Reason
Improves scalability, maintainability, independent deployment, and aligns with modern industry practices.

### Alternatives Considered
- Monolithic application

### Status
Accepted


## ED-002

### Decision
Use MongoDB Atlas with Mongoose.

### Reason
Cloud-hosted database, free development tier, flexible document model, and strong integration with Node.js through Mongoose.

### Alternatives Considered
- Local MongoDB
- MySQL
- PostgreSQL

### Status
Accepted


## ED-003

### Decision
Store user storage usage and limits in bytes.

### Reason
Bytes are the native unit for file systems and avoid repeated conversions. The frontend can convert bytes into KB, MB, or GB for display.

### Status
Accepted