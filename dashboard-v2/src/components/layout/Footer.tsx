export default function Footer() {
  return (
    <footer className="w-full border-t border-border bg-surface py-6 px-4 sm:px-8 flex flex-col gap-6 md:flex-row md:items-center justify-between text-xs leading-5 text-text-muted">
      <div>
        <p className="font-semibold text-text mb-1">PTI-Honeypot</p>
        <p>© 2024 PTI-Honeypot Cyber Defense. All Rights Reserved.</p>
        <p>Security Clearance Level 4 Required.</p>
      </div>
      <div className="flex flex-wrap gap-6">
        <a href="#" className="hover:text-primary">Privacy Policy</a>
        <a href="#" className="hover:text-primary">Terms of Engagement</a>
        <a href="#" className="hover:text-primary">Support</a>
      </div>
    </footer>
  );
}