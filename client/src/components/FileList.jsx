import Icon from './Icon';
import { formatBytes, formatDate } from '../services/formatters';

function FileList({ files, onPreview, onDownload, onShare, onDelete }) {
  if (!files.length) {
    return (
      <div className="empty-files">
        <div className="empty-file-icon">
          <Icon name="upload" size={20} />
        </div>
        <strong>Your vault is empty</strong>
        <p>Upload your first file to see it here.</p>
      </div>
    );
  }

  return (
    <div className="file-list">
      {files.map((file) => (
        <div className="file-row" key={file.id}>
          <div className="file-type">
            {file.mimeType?.split('/')[1]?.slice(0, 3).toUpperCase() || 'FILE'}
          </div>
          <div className="file-name">
            <strong>{file.originalName}</strong>
            <small>{formatDate(file.createdAt)}</small>
          </div>
          <span className="file-size">{formatBytes(file.size)}</span>
          <div className="file-actions">
            <button aria-label="Preview file" title="Preview file" onClick={() => onPreview(file)}>
              <Icon name="eye" size={17} />
            </button>
            <button
              aria-label="Create share link"
              title="Create share link"
              onClick={() => onShare(file)}
            >
              <Icon name="link" size={17} />
            </button>
            <button aria-label="Download" title="Download" onClick={() => onDownload(file)}>
              <Icon name="download" size={17} />
            </button>
            <button aria-label="Delete" title="Delete" onClick={() => onDelete(file)}>
              <Icon name="trash" size={17} />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

export default FileList;
