function Icon({ name, size = 18 }) {
  const paths = {
    grid: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
    search: 'm21 21-4.35-4.35m2.35-5.65a8 8 0 1 1-16 0 8 8 0 0 1 16 0Z',
    upload: 'M12 16V4m0 0L7 9m5-5 5 5M5 20h14',
    share:
      'M18 8a3 3 0 1 0-2.83-4A3 3 0 0 0 15 5c0 .34.06.66.16.96L8.84 9.5A3 3 0 0 0 7 9a3 3 0 1 0 1.84 5.5l6.32 3.54A3 3 0 1 0 17 16c-.34 0-.66.06-.96.16l-6.32-3.54c.18-.5.28-1.05.28-1.62s-.1-1.12-.28-1.62l6.32-3.54c.3.1.62.16.96.16Z',
    settings:
      'M12 15.4a3.4 3.4 0 1 0 0-6.8 3.4 3.4 0 0 0 0 6.8Zm0-12v2m0 13.2v2M4.44 4.44l1.42 1.42m12.28 12.28 1.42 1.42M2 12h2m16 0h2M4.44 19.56l1.42-1.42M18.14 5.86l1.42-1.42',
    download: 'M12 4v11m0 0 5-5m-5 5-5-5M5 20h14',
    eye: 'M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Zm9.5 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z',
    trash: 'M5 7h14m-9 4v5m4-5v5M9 7V4h6v3m-8 0 1 13h8l1-13',
    check: 'm5 12 4 4L19 6',
    link: 'M10 13a5 5 0 0 0 7.07.07l2-2a5 5 0 0 0-7.07-7.07l-1.15 1.15m3.15 5.85a5 5 0 0 0-7.07-.07l-2 2a5 5 0 0 0 7.07 7.07l1.15-1.15',
    copy: 'M8 8h10v12H8zM6 16H4V4h10v2',
    close: 'M6 6l12 12M18 6 6 18',
    shield: 'M12 3 20 6v6c0 5-3.4 8.3-8 10-4.6-1.7-8-5-8-10V6l8-3Z',
    moon: 'M20.5 15.5A8.5 8.5 0 0 1 8.5 3.5 8.5 8.5 0 1 0 20.5 15.5Z',
    sun: 'M12 3v2m0 14v2M3 12h2m14 0h2M5.64 5.64l1.42 1.42m9.9 9.9 1.4 1.4m0-12.72-1.4 1.42m-9.9 9.9-1.42 1.4M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z',
  };

  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d={paths[name]} />
    </svg>
  );
}

export default Icon;
