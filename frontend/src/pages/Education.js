import React, { useState, useEffect } from 'react';
import './Education.css';

function Education() {
    const awarenessTips = [
        "Think before you click — hover over links to preview where they go.",
        "Verify the sender — even if the name looks familiar, double-check the email address.",
        "Check domain names carefully — scammers often use slight variations.",
        "Watch out for urgent or threatening language — it's a common phishing tactic.",
        "Don’t download unexpected attachments — especially if you weren’t expecting one.",
        "Use multi-factor authentication (MFA) wherever possible.",
        "Never share personal or sensitive info via email.",
        "Keep your browser, antivirus, and software up to date.",
        "Report suspicious emails to your IT team or email provider.",
        "Stay informed — phishing tactics evolve, so stay educated.",
        "Beware of 'too good to be true' offers like fake giveaways or job posts.",
        "Look for grammar and spelling mistakes — they’re often signs of phishing.",
        "Don’t trust logos and branding alone — they can be faked.",
        "Be cautious with QR codes from emails or flyers — verify the source.",
        "Use a password manager — it can help detect phishing sites.",
        "Avoid logging in to accounts via links in emails — go directly to the site.",
        "Always confirm requests for gift cards or money transfers — especially if 'urgent'.",
        "Trust your instincts — if something feels suspicious, investigate further.",
        "Never ignore browser security warnings about unsafe websites.",
        "Lock down your social media profiles — scammers gather intel from your posts."
    ];

    const [articles, setArticles] = useState([]);
    const [currentIndex, setCurrentIndex] = useState(0);
    const [currentTip, setCurrentTip] = useState(awarenessTips[0]);

    const handleNextTip = () => {
        const nextIndex = (currentIndex + 1) % awarenessTips.length;
        setCurrentIndex(nextIndex);
        setCurrentTip(awarenessTips[nextIndex]);
    };

    const handlePrevTip = () => {
        const prevIndex = (currentIndex - 1 + awarenessTips.length) % awarenessTips.length;
        setCurrentIndex(prevIndex);
        setCurrentTip(awarenessTips[prevIndex]);
    };

    useEffect(() => {
        const sampleArticles = [
            {
                title: "Latest phishing attacks and news | The Daily Swig",
                summary: "The Daily Swig offers coverage of the latest phishing scams and recent phishing attacks, helping organizations to stay ahead of the threat.",
                link: "https://portswigger.net/daily-swig/phishing"
            },
            {
                title: "10 Cyber Security Trends For 2025",
                summary: "Zero trust is one of the top cyber security trends in 2025, with more and more organizations adopting micro-segmentation, user context checks, ...",
                link: "https://www.sentinelone.com/cybersecurity-101/cybersecurity/cyber-security-trends/"
            },
            {
                title: "The Anatomy of a Phishing Email",
                summary: "As with the subject line, the body copy of a phishing email is typically employs urgent language designed to encourage the reader to act without thinking.",
                link: "https://www.varonis.com/blog/spot-phishing-scam"
            }
        ];
        setArticles(sampleArticles);
    }, []);

    return (
        <div className="education-container">
            <header className="hero-section">
                <h1>Phishing Awareness & Online Safety</h1>
                <p>One Click Can Cost You - Stay Informed.</p>
            </header>

            {/* Videos Section */}
            <section className="content-section">
                <h2>Educational Videos</h2>
                <div className="video-grid">
                    <div className="video-card">
                        <iframe src="https://www.youtube.com/embed/Y7zNlEMDmI4?si=m-xuUgOqMO7vVbbH" title="What is phishing?" allowFullScreen></iframe>
                        <p>What is phishing? Learn how this attack works</p>
                    </div>
                    <div className="video-card">
                        <iframe src="https://www.youtube.com/embed/Vkjekr6jacg?si=Di_UTShE-k49U5bk" title="What is Ransomware" allowFullScreen></iframe>
                        <p>What is Ransomware, and What You Can Do to Stay Protected</p>
                    </div>
                    <div className="video-card">
                        <iframe src="https://www.youtube.com/embed/0mvCeNsTa1g?si=aFfb_tf95K4hh3Qh" title="What is 2FA" allowFullScreen></iframe>
                        <p>What is Two-Factor Authentication? (2FA)</p>
                    </div>
                    <div className="video-card">
                        <iframe src="https://www.youtube.com/embed/L-xBDRKsa8Q?si=m7nmEKsVF5r9Y69c" title="Cyber Security Animation" allowFullScreen></iframe>
                        <p>Cyber Security Awareness Animation</p>
                    </div>
                    <div className="video-card">
                        <iframe src="https://www.youtube.com/embed/o0btqyGWIQw" title="Phishing Awareness Video" allowFullScreen></iframe>
                        <p>Spot Phishing Emails | Here is how</p>
                    </div>
                    <div className="video-card">
                        <iframe src="https://www.youtube.com/embed/dGEdc8mVc5E?si=CfOellCiONNtZmxa" title="Phishing Types" allowFullScreen></iframe>
                        <p>Phishing, Vishing, and SMiShing | Phishing Attacks</p>
                    </div>
                </div>
            </section>

            {/* Blog Section */}
            <section className="content-section">
                <h2>Latest News & Articles</h2>
                <div className="blog-posts">
                    {articles.length > 0 ? (
                        articles.map((article, index) => (
                            <div key={index} className="blog-card">
                                <h3>{article.title}</h3>
                                <p>{article.summary}</p>
                                <a href={article.link} target="_blank" rel="noopener noreferrer">Read More</a>
                            </div>
                        ))
                    ) : (
                        <p>Loading articles...</p>
                    )}
                </div>
            </section>

            {/* Awareness Tips */}
            <section className="content-section">
              <h2>Awareness Tips</h2>
              <div className="tip-box fade-in">
               
                  <span className="arrow-icon" onClick={handlePrevTip}>🡐</span>
                  <p>💡 {currentTip}</p>
                  <span className="arrow-icon" onClick={handleNextTip}>🡒</span>
                
              </div>

            </section>


        </div>
    );
}

export default Education;
