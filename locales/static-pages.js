const STATIC_LANGS = {
  en: { flag: "EN", flagCode: "us", dir: "ltr" },
  he: { flag: "IL", flagCode: "il", dir: "rtl" },
  de: { flag: "DE", flagCode: "de", dir: "ltr" },
  ja: { flag: "JP", flagCode: "jp", dir: "ltr" },
  ko: { flag: "KR", flagCode: "kr", dir: "ltr" },
  fr: { flag: "FR", flagCode: "fr", dir: "ltr" },
  pt: { flag: "BR", flagCode: "br", dir: "ltr" },
};

const STATIC_T = {
  en: {
    back_scanner: "Back to scanner",
    home: "Home",
    skills: "Skills",
    extensions: "Extensions",
    terms: "Terms",
    privacy: "Privacy",
    contact: "// contact",
    contact_title: "Talk to Cyber Guardian Scan",
    contact_sub: "Use this form for custom packages, enterprise pricing, procurement, support, or security questions. Your message stays inside the site and goes to the right inbox.",
    request_type: "Request type",
    work_email: "Work email",
    name: "Name",
    company: "Company",
    message: "Message",
    opt_sales: "Sales / custom package",
    opt_enterprise: "Enterprise / procurement",
    opt_support: "Support",
    opt_security: "Security issue",
    contact_placeholder: "Tell us what you need: scan volume, package type, security question, or support issue.",
    send_message: "Send Message",
    sending: "Sending...",
    contact_direct: "Business and pricing messages are routed to sales@cyberguardianscan.com. Support and security messages are routed to support@cyberguardianscan.com.",
    contact_success: "Thanks. We received your message and will reply soon.",
    contact_failed: "Could not send message.",
    invalid_email: "Please enter a valid email address.",
    short_message: "Please add a short message.",
    skills_title: "Scan an AI Skill before installing it.",
    skills_eyebrow: "AI Skills Security Scanner",
    skills_sub: "Claude Skills, Cursor Skills, custom prompts - any of them can contain hidden prompt injection, role confusion, or malicious payloads. Paste the code, get a verdict in seconds.",
    open_scanner: "Open Scanner",
    skill_f1: "Prompt Injection Detection",
    skill_f1d: "Catches hidden instructions, jailbreaks, and prompt override attempts.",
    skill_f2: "Role Confusion",
    skill_f2d: "Detects skills that try to make the AI assume a different identity.",
    skill_f3: "Hidden Payloads",
    skill_f3d: "Finds Base64, Unicode, and zero-width character obfuscation.",
    need_mcp: "Need MCP scanning too?",
    need_mcp_sub: "Same scanner, same account, full MCP coverage.",
    mcp_scanner: "MCP Security Scanner",
    ext_title: "Scan an IDE extension before installing it.",
    ext_eyebrow: "IDE Extension Security Scanner",
    ext_sub: "VS Code, Cursor, and JetBrains extensions can read every file you open. A malicious one can exfiltrate credentials, source code, and secrets. Scan first.",
    ext_incident_t: "Why this matters",
    ext_incident_d: "Developer extensions run with broad access. Malicious or compromised extensions can steal API keys, source code, SSH credentials, and project files.",
    ext_f1: "Credential Theft",
    ext_f1d: "Detects code that reads SSH keys, npm tokens, git config, AWS credentials, and environment secrets.",
    ext_f2: "Data Exfiltration",
    ext_f2d: "Finds network calls that send your code or files to external servers.",
    ext_f3: "Supply Chain Attacks",
    ext_f3d: "Detects typosquatting, dependency confusion, and risky install scripts.",
    privacy_title: "Privacy Policy",
    terms_title: "Terms of Service",
    updated: "Last updated: May 28, 2026",
    privacy_body: `
      <h2>1. What We Collect</h2>
      <p>Cyber Guardian Scan collects the minimum data needed to provide security scan results and protect the service from abuse.</p>
      <ul><li><strong>Code submitted for scanning:</strong> processed for security analysis and may be sent to a third-party AI provider.</li><li><strong>Scan metadata:</strong> scope, status, score, threat count, summaries, timestamps, and one-way hashes for cache and quota enforcement.</li><li><strong>Usage keys:</strong> IP-derived keys may be hashed or shortened for rate limits.</li><li><strong>Product analytics events:</strong> anonymous page views, scan starts/completions/failures, selected scan scope, country-level geo headers, language, device/browser class, referrer domain, Sales clicks, and signup/contact events. Raw IP addresses are not stored.</li><li><strong>Email/contact data:</strong> collected only when you subscribe or contact us.</li></ul>
      <h2>2. Submitted Code</h2><div class="warn">Do not submit code unless you have permission to analyze it. Avoid pasting secrets, private keys, customer data, or highly confidential source code.</div>
      <p>Submitted code may be sent to a third-party AI provider for analysis. Cyber Guardian Scan does not intentionally store full submitted code in the database.</p>
      <h2>3. What We Do Not Do</h2><div class="good"><strong>We do not sell personal data.</strong><br><br><strong>We do not use third-party advertising trackers.</strong><br><br><strong>We do not execute submitted code.</strong> Scans are static/AI-assisted analysis only.</div>
      <h2>4. How We Use Data</h2><ul><li>Provide scan verdicts and recommendations.</li><li>Prevent abuse through rate limits and quotas.</li><li>Generate aggregate dashboard statistics.</li><li>Understand product usage, popular scan types, countries, languages, devices, referrers, and conversion from visit to scan or contact request.</li><li>Improve detection quality and reliability.</li></ul>
      <h2>5. Third-Party Providers</h2><p>The service may use a third-party AI provider, Vercel, Supabase, and Resend for analysis, hosting, storage, email notifications, contact messages, and anonymous product analytics.</p>
      <h2>6. Data Retention</h2><ul><li>Submitted scan code: processed transiently and not intentionally stored.</li><li>Scan cache: up to 1 hour.</li><li>Usage windows: retained for quota periods.</li><li>Product analytics events: retained for product improvement and business reporting.</li><li>Contact/subscriber emails: retained until deletion request or operational cleanup.</li></ul>
      <h2>7. Local Storage</h2><p>The site may use browser local storage for language preference, developer settings, and client-side display state.</p>
      <h2>8. Your Rights</h2><p>For privacy or support requests, use <a href="/contact.html?type=support">support@cyberguardianscan.com</a>. For sales or business requests, use <a href="/contact.html?type=sales">sales@cyberguardianscan.com</a>.</p>
      <h2>9. Children</h2><p>The service is not directed to children under 13.</p>
      <h2>10. Changes</h2><p>If this policy changes, the updated version will be posted here.</p>`,
    terms_body: `
      <h2>1. The Service</h2><p>Cyber Guardian Scan is a security scanning tool for MCP servers, AI Skills, IDE extensions, and related code.</p>
      <h2>2. Advisory Results</h2><div class="warn">Scan results are advisory only. No scanner can detect every vulnerability, malicious behavior, supply-chain issue, or prompt injection.</div>
      <h2>3. Code Submission Rules</h2><ul><li>You must have permission to submit the code you scan.</li><li>Do not submit secrets, private keys, credentials, customer data, or confidential third-party code without authorization.</li><li>Submitted code may be sent to a third-party AI provider for analysis.</li><li>You may not use the service to attack or bypass another system.</li></ul>
      <h2>4. Acceptable Use</h2><ul><li>Do not exceed or bypass limits or abuse protections.</li><li>Do not automate high-volume scans without written permission.</li><li>Do not reverse engineer, scrape, or resell the service as your own scanner.</li><li>Do not submit illegal content or harmful code for systems you do not own.</li></ul>
      <h2>5. Free Beta Access</h2><p>The free beta currently allows 10 scans per month. If you need larger scan volume for a team, research project, or organization, contact sales@cyberguardianscan.com.</p>
      <h2>6. Availability and Changes</h2><p>The service may be changed, paused, rate-limited, or discontinued at any time.</p>
      <h2>7. No Warranty</h2><p>The service is provided "as is" and "as available", without warranties of any kind.</p>
      <h2>8. Limitation of Liability</h2><p>Cyber Guardian Scan and its operators are not liable for damages arising from scan results, missed detections, false positives, downtime, or security incidents.</p>
      <h2>9. Governing Law</h2><p>These terms are governed by the laws of Israel, unless mandatory local law requires otherwise.</p>
      <h2>10. Contact</h2><p>For support or legal questions, use <a href="/contact.html?type=support">support@cyberguardianscan.com</a>. For larger scan-volume requests, use <a href="/contact.html?type=sales">sales@cyberguardianscan.com</a>.</p>`
  },
};

STATIC_T.de = { ...STATIC_T.en,
  back_scanner: "Zuruck zum Scanner", contact: "// kontakt", contact_title: "Sprechen Sie mit Cyber Guardian Scan", contact_sub: "Nutzen Sie dieses Formular fur individuelle Pakete, Enterprise-Preise, Einkauf, Support oder Sicherheitsfragen.", request_type: "Anfrageart", work_email: "Geschaftliche E-Mail", name: "Name", company: "Unternehmen", message: "Nachricht", opt_sales: "Sales / individuelles Paket", opt_enterprise: "Enterprise / Einkauf", opt_support: "Support", opt_security: "Sicherheitsproblem", contact_placeholder: "Beschreiben Sie, was Sie brauchen: Scan-Volumen, Paket, Sicherheitsfrage oder Support.", send_message: "Nachricht senden", sending: "Wird gesendet...", contact_direct: "Business- und Preisanfragen gehen an sales@cyberguardianscan.com. Support- und Sicherheitsanfragen gehen an support@cyberguardianscan.com.", contact_success: "Danke. Wir haben Ihre Nachricht erhalten.", invalid_email: "Bitte geben Sie eine gultige E-Mail-Adresse ein.", short_message: "Bitte schreiben Sie eine kurze Nachricht.", skills_title: "Scannen Sie einen AI Skill vor der Installation.", skills_eyebrow: "AI Skills Security Scanner", skills_sub: "Claude Skills, Cursor Skills und eigene Prompts konnen versteckte Prompt-Injection oder Schadcode enthalten.", open_scanner: "Scanner offnen", need_mcp: "Brauchen Sie auch MCP-Scanning?", need_mcp_sub: "Derselbe Scanner, dasselbe Konto, volle MCP-Abdeckung.", mcp_scanner: "MCP Security Scanner", ext_title: "Scannen Sie eine IDE-Erweiterung vor der Installation.", ext_eyebrow: "IDE Extension Security Scanner", ext_sub: "VS Code-, Cursor- und JetBrains-Erweiterungen konnen Dateien lesen. Scannen Sie zuerst.", ext_incident_t: "Warum das wichtig ist", ext_incident_d: "Entwickler-Erweiterungen laufen mit weitreichendem Zugriff und konnen Secrets oder Quellcode stehlen.", privacy_title: "Datenschutzerklarung", terms_title: "Nutzungsbedingungen", updated: "Zuletzt aktualisiert: 28. Mai 2026" };
STATIC_T.fr = { ...STATIC_T.en,
  back_scanner: "Retour au scanner", contact: "// contact", contact_title: "Contacter Cyber Guardian Scan", contact_sub: "Utilisez ce formulaire pour les offres sur mesure, tarifs enterprise, achat, support ou questions securite.", request_type: "Type de demande", work_email: "Email professionnel", name: "Nom", company: "Entreprise", message: "Message", opt_sales: "Vente / offre sur mesure", opt_enterprise: "Enterprise / achat", opt_support: "Support", opt_security: "Probleme de securite", contact_placeholder: "Expliquez votre besoin: volume de scans, type d'offre, securite ou support.", send_message: "Envoyer", sending: "Envoi...", contact_direct: "Les demandes commerciales vont a sales@cyberguardianscan.com. Le support et la securite vont a support@cyberguardianscan.com.", contact_success: "Merci. Nous avons recu votre message.", invalid_email: "Veuillez saisir un email valide.", short_message: "Ajoutez un court message.", skills_title: "Scannez un AI Skill avant de l'installer.", skills_eyebrow: "Scanner de securite AI Skills", skills_sub: "Claude Skills, Cursor Skills et prompts personnalises peuvent contenir des injections cachees ou charges malveillantes.", open_scanner: "Ouvrir le scanner", need_mcp: "Besoin aussi du scan MCP ?", need_mcp_sub: "Meme scanner, meme compte, couverture MCP complete.", mcp_scanner: "Scanner de securite MCP", ext_title: "Scannez une extension IDE avant installation.", ext_eyebrow: "Scanner de securite IDE", ext_sub: "Les extensions VS Code, Cursor et JetBrains peuvent lire vos fichiers. Scannez d'abord.", ext_incident_t: "Pourquoi c'est important", ext_incident_d: "Les extensions developpeur ont souvent un acces large et peuvent voler secrets ou code source.", privacy_title: "Politique de confidentialite", terms_title: "Conditions d'utilisation", updated: "Derniere mise a jour : 28 mai 2026" };
STATIC_T.pt = { ...STATIC_T.en,
  back_scanner: "Voltar ao scanner", contact: "// contato", contact_title: "Fale com a Cyber Guardian Scan", contact_sub: "Use este formulario para pacotes personalizados, precos enterprise, compras, suporte ou seguranca.", request_type: "Tipo de pedido", work_email: "Email profissional", name: "Nome", company: "Empresa", message: "Mensagem", opt_sales: "Vendas / pacote personalizado", opt_enterprise: "Enterprise / compras", opt_support: "Suporte", opt_security: "Problema de seguranca", contact_placeholder: "Conte o que voce precisa: volume de scans, pacote, seguranca ou suporte.", send_message: "Enviar mensagem", sending: "Enviando...", contact_direct: "Mensagens comerciais vao para sales@cyberguardianscan.com. Suporte e seguranca vao para support@cyberguardianscan.com.", contact_success: "Obrigado. Recebemos sua mensagem.", invalid_email: "Insira um email valido.", short_message: "Adicione uma mensagem curta.", skills_title: "Escaneie um AI Skill antes de instalar.", skills_eyebrow: "Scanner de seguranca AI Skills", skills_sub: "Claude Skills, Cursor Skills e prompts podem conter injecao de prompt ou cargas maliciosas.", open_scanner: "Abrir scanner", need_mcp: "Tambem precisa escanear MCP?", need_mcp_sub: "Mesmo scanner, mesma conta, cobertura MCP completa.", mcp_scanner: "Scanner de seguranca MCP", ext_title: "Escaneie uma extensao IDE antes de instalar.", ext_eyebrow: "Scanner de seguranca IDE", ext_sub: "Extensoes VS Code, Cursor e JetBrains podem ler seus arquivos. Escaneie primeiro.", ext_incident_t: "Por que isso importa", ext_incident_d: "Extensoes de desenvolvedor tem acesso amplo e podem roubar segredos ou codigo-fonte.", privacy_title: "Politica de Privacidade", terms_title: "Termos de Servico", updated: "Atualizado em: 28 de maio de 2026" };
STATIC_T.he = { ...STATIC_T.en,
  back_scanner: "חזרה לסורק", home: "בית", skills: "Skills", extensions: "Extensions", terms: "תנאים", privacy: "פרטיות", contact: "// יצירת_קשר", contact_title: "דברו עם Cyber Guardian Scan", contact_sub: "השתמשו בטופס לחבילות מותאמות, מחיר ארגוני, רכש, תמיכה או שאלות אבטחה. ההודעה נשארת באתר ומנותבת לתיבה הנכונה.", request_type: "סוג פנייה", work_email: "אימייל עבודה", name: "שם", company: "חברה", message: "הודעה", opt_sales: "מכירות / חבילה מותאמת", opt_enterprise: "Enterprise / רכש", opt_support: "תמיכה", opt_security: "נושא אבטחה", contact_placeholder: "ספרו מה אתם צריכים: נפח סריקות, סוג חבילה, שאלת אבטחה או תמיכה.", send_message: "שליחת הודעה", sending: "שולח...", contact_direct: "פניות עסקיות ומחירים מנותבות אל sales@cyberguardianscan.com. תמיכה ואבטחה מנותבות אל support@cyberguardianscan.com.", contact_success: "תודה. קיבלנו את ההודעה ונחזור אליך בקרוב.", contact_failed: "לא ניתן לשלוח את ההודעה.", invalid_email: "נא להזין כתובת אימייל תקינה.", short_message: "נא להוסיף הודעה קצרה.", skills_title: "סרוק AI Skill לפני התקנה.", skills_eyebrow: "סורק אבטחה ל-AI Skills", skills_sub: "Claude Skills, Cursor Skills ופרומפטים מותאמים יכולים לכלול Prompt Injection מוסתר, בלבול תפקידים או מטענים זדוניים.", open_scanner: "פתח סורק", need_mcp: "צריך גם סריקת MCP?", need_mcp_sub: "אותו סורק, אותו חשבון, כיסוי MCP מלא.", mcp_scanner: "סורק אבטחת MCP", ext_title: "סרוק הרחבת IDE לפני התקנה.", ext_eyebrow: "סורק אבטחה להרחבות IDE", ext_sub: "הרחבות VS Code, Cursor ו-JetBrains יכולות לקרוא קבצים. הרחבה זדונית יכולה לגנוב קוד, סודות ופרטי גישה. סרוק קודם.", ext_incident_t: "למה זה חשוב", ext_incident_d: "הרחבות פיתוח רצות עם גישה רחבה ועלולות לגנוב API keys, קוד מקור, SSH credentials וקבצי פרויקט.", ext_f1: "גניבת Credentials", ext_f1d: "מזהה קוד שקורא SSH keys, npm tokens, AWS credentials וסודות סביבה.", ext_f2: "הברחת מידע", ext_f2d: "מזהה קריאות רשת ששולחות קוד או קבצים לשרתים חיצוניים.", ext_f3: "התקפות שרשרת אספקה", ext_f3d: "מזהה typosquatting, dependency confusion וסקריפטים מסוכנים בהתקנה.", privacy_title: "מדיניות פרטיות", terms_title: "תנאי שימוש", updated: "עודכן לאחרונה: 28 במאי 2026" };
STATIC_T.ja = { ...STATIC_T.en, back_scanner: "スキャナーへ戻る", contact_title: "Cyber Guardian Scan に連絡", contact_sub: "カスタムプラン、Enterprise 価格、購買、サポート、セキュリティ質問はこちらから送信できます。", request_type: "問い合わせ種別", work_email: "仕事用メール", name: "名前", company: "会社", message: "メッセージ", opt_sales: "営業 / カスタムプラン", opt_enterprise: "Enterprise / 購買", opt_support: "サポート", opt_security: "セキュリティ問題", contact_placeholder: "必要な内容、スキャン量、プラン、サポート内容を入力してください。", send_message: "送信", sending: "送信中...", contact_success: "ありがとうございます。メッセージを受け取りました。", invalid_email: "有効なメールアドレスを入力してください。", short_message: "短いメッセージを入力してください。", skills_title: "AI Skill をインストール前にスキャン。", skills_eyebrow: "AI Skills セキュリティスキャナー", open_scanner: "スキャナーを開く", ext_title: "IDE 拡張機能をインストール前にスキャン。", ext_eyebrow: "IDE 拡張セキュリティスキャナー", privacy_title: "プライバシーポリシー", terms_title: "利用規約", updated: "最終更新日: 2026年5月28日" };
STATIC_T.ko = { ...STATIC_T.en, back_scanner: "스캐너로 돌아가기", contact_title: "Cyber Guardian Scan에 문의", contact_sub: "맞춤 패키지, Enterprise 가격, 구매, 지원 또는 보안 질문을 이 양식으로 보내세요.", request_type: "요청 유형", work_email: "업무 이메일", name: "이름", company: "회사", message: "메시지", opt_sales: "영업 / 맞춤 패키지", opt_enterprise: "Enterprise / 구매", opt_support: "지원", opt_security: "보안 이슈", contact_placeholder: "필요한 내용, 스캔 용량, 패키지, 보안 질문 또는 지원 이슈를 적어주세요.", send_message: "메시지 보내기", sending: "보내는 중...", contact_success: "감사합니다. 메시지를 받았습니다.", invalid_email: "올바른 이메일 주소를 입력하세요.", short_message: "짧은 메시지를 입력하세요.", skills_title: "AI Skill 설치 전 스캔하세요.", skills_eyebrow: "AI Skills 보안 스캐너", open_scanner: "스캐너 열기", ext_title: "IDE 확장 설치 전 스캔하세요.", ext_eyebrow: "IDE 확장 보안 스캐너", privacy_title: "개인정보 처리방침", terms_title: "서비스 약관", updated: "마지막 업데이트: 2026년 5월 28일" };

for (const code of ["de", "fr", "pt", "he", "ja", "ko"]) {
  STATIC_T[code].privacy_body = `
    <h2>${STATIC_T[code].privacy_title}</h2>
    <p>${code === "he" ? "Cyber Guardian Scan אוסף את המידע המינימלי הדרוש להפעלת הסורק, מניעת שימוש לרעה, שמירת סטטיסטיקות ותפעול פניות משתמשים." : code === "de" ? "Cyber Guardian Scan erfasst nur die Daten, die fur Scan-Ergebnisse, Missbrauchsschutz, Statistiken und Kontaktanfragen erforderlich sind." : code === "fr" ? "Cyber Guardian Scan collecte uniquement les donnees necessaires aux scans, a la protection contre les abus, aux statistiques et aux demandes de contact." : code === "pt" ? "Cyber Guardian Scan coleta apenas os dados necessarios para scans, protecao contra abuso, estatisticas e contatos." : code === "ja" ? "Cyber Guardian Scan は、スキャン、悪用防止、統計、問い合わせ対応に必要な最小限のデータのみを収集します。" : "Cyber Guardian Scan는 스캔, 악용 방지, 통계 및 문의 처리를 위해 필요한 최소 데이터만 수집합니다."}</p>
    <ul><li>${code === "he" ? "קוד שנשלח לסריקה עשוי להישלח לספק AI צד שלישי לניתוח." : code === "de" ? "Eingereichter Code kann zur Analyse an einen Drittanbieter fur KI gesendet werden." : code === "fr" ? "Le code soumis peut etre envoye a un fournisseur IA tiers pour analyse." : code === "pt" ? "O codigo enviado pode ser encaminhado a um provedor de IA de terceiros para analise." : code === "ja" ? "送信されたコードは解析のため第三者 AI プロバイダーへ送られる場合があります。" : "제출된 코드는 분석을 위해 제3자 AI 제공업체로 전송될 수 있습니다."}</li><li>${code === "he" ? "איננו מוכרים מידע אישי ואיננו מריצים את הקוד שנשלח." : code === "de" ? "Wir verkaufen keine personenbezogenen Daten und fuhren eingereichten Code nicht aus." : code === "fr" ? "Nous ne vendons pas les donnees personnelles et n'executons pas le code soumis." : code === "pt" ? "Nao vendemos dados pessoais e nao executamos o codigo enviado." : code === "ja" ? "個人データを販売せず、送信コードを実行しません。" : "개인 데이터를 판매하지 않으며 제출된 코드를 실행하지 않습니다."}</li><li>${code === "he" ? "אימיילים ופניות נשמרים לצורך מענה ותפעול השירות." : code === "de" ? "E-Mails und Kontaktanfragen werden zur Beantwortung und fur den Betrieb gespeichert." : code === "fr" ? "Les emails et messages sont conserves pour repondre et exploiter le service." : code === "pt" ? "Emails e mensagens sao mantidos para resposta e operacao do servico." : code === "ja" ? "メールと問い合わせは返信と運用のため保持されます。" : "이메일과 문의는 응답 및 서비스 운영을 위해 보관됩니다."}</li></ul>
    <h2>${code === "he" ? "צדדים שלישיים ושמירה" : code === "de" ? "Drittanbieter und Aufbewahrung" : code === "fr" ? "Fournisseurs tiers et conservation" : code === "pt" ? "Terceiros e retencao" : code === "ja" ? "第三者サービスと保存期間" : "제3자 서비스 및 보관"}</h2>
    <p>${code === "he" ? "השירות עשוי להשתמש ב-Vercel, Supabase, Resend וספק AI צד שלישי. ניתן לפנות אלינו לגבי גישה, תיקון או מחיקה דרך טופס התמיכה." : code === "de" ? "Der Dienst kann Vercel, Supabase, Resend und einen Drittanbieter fur KI verwenden. Anfragen zu Zugriff, Korrektur oder Loschung konnen uber das Support-Formular gestellt werden." : code === "fr" ? "Le service peut utiliser Vercel, Supabase, Resend et un fournisseur IA tiers. Les demandes d'acces, correction ou suppression passent par le formulaire support." : code === "pt" ? "O servico pode usar Vercel, Supabase, Resend e um provedor de IA de terceiros. Solicite acesso, correcao ou exclusao pelo formulario de suporte." : code === "ja" ? "本サービスは Vercel、Supabase、Resend、第三者 AI プロバイダーを使用する場合があります。アクセス、修正、削除の依頼はサポートフォームから行えます。" : "이 서비스는 Vercel, Supabase, Resend 및 제3자 AI 제공업체를 사용할 수 있습니다. 접근, 수정 또는 삭제 요청은 지원 양식으로 보내세요."}</p>`;
  STATIC_T[code].terms_body = `
    <h2>${STATIC_T[code].terms_title}</h2>
    <p>${code === "he" ? "Cyber Guardian Scan הוא כלי סריקת אבטחה ל-MCP servers, AI Skills, הרחבות IDE וקוד קשור. התוצאות הן המלצה בלבד ואינן מבטיחות גילוי מלא של כל איום." : code === "de" ? "Cyber Guardian Scan ist ein Sicherheitsscanner fur MCP-Server, AI Skills, IDE-Erweiterungen und verwandten Code. Ergebnisse sind nur Hinweise und garantieren keine vollstandige Erkennung." : code === "fr" ? "Cyber Guardian Scan est un scanner de securite pour MCP servers, AI Skills, extensions IDE et code lie. Les resultats sont indicatifs et ne garantissent pas une detection complete." : code === "pt" ? "Cyber Guardian Scan e um scanner de seguranca para MCP servers, AI Skills, extensoes IDE e codigo relacionado. Os resultados sao consultivos e nao garantem deteccao completa." : code === "ja" ? "Cyber Guardian Scan は MCP サーバー、AI Skills、IDE 拡張、関連コード向けのセキュリティスキャナーです。結果は助言であり、完全な検出を保証しません。" : "Cyber Guardian Scan는 MCP 서버, AI Skills, IDE 확장 및 관련 코드를 위한 보안 스캐너입니다. 결과는 참고용이며 모든 위협 탐지를 보장하지 않습니다."}</p>
    <ul><li>${code === "he" ? "מותר לשלוח רק קוד שיש לך הרשאה לבדוק." : code === "de" ? "Sie durfen nur Code einreichen, den Sie prufen durfen." : code === "fr" ? "Vous ne devez soumettre que du code que vous etes autorise a analyser." : code === "pt" ? "Envie apenas codigo que voce tem permissao para analisar." : code === "ja" ? "解析する権限があるコードのみ送信してください。" : "분석 권한이 있는 코드만 제출하세요."}</li><li>${code === "he" ? "אין לשלוח סודות, מפתחות פרטיים, נתוני לקוחות או קוד חסוי ללא הרשאה." : code === "de" ? "Senden Sie keine Secrets, privaten Schlussel, Kundendaten oder vertraulichen Code ohne Berechtigung." : code === "fr" ? "Ne soumettez pas de secrets, cles privees, donnees client ou code confidentiel sans autorisation." : code === "pt" ? "Nao envie segredos, chaves privadas, dados de clientes ou codigo confidencial sem autorizacao." : code === "ja" ? "秘密情報、秘密鍵、顧客データ、機密コードを無断で送信しないでください。" : "비밀, 개인 키, 고객 데이터 또는 기밀 코드를 권한 없이 제출하지 마세요."}</li><li>${code === "he" ? "אין לעקוף מגבלות, לנצל לרעה את השירות או להשתמש בו לתקיפת מערכות שאינך מנהל." : code === "de" ? "Umgehen Sie keine Limits und verwenden Sie den Dienst nicht zum Angriff auf fremde Systeme." : code === "fr" ? "Ne contournez pas les limites et n'utilisez pas le service pour attaquer des systemes tiers." : code === "pt" ? "Nao contorne limites nem use o servico para atacar sistemas de terceiros." : code === "ja" ? "制限を回避したり、他者のシステム攻撃に使用したりしないでください。" : "제한을 우회하거나 타 시스템 공격에 사용하지 마세요."}</li></ul>
    <h2>${code === "he" ? "אחריות ויצירת קשר" : code === "de" ? "Haftung und Kontakt" : code === "fr" ? "Responsabilite et contact" : code === "pt" ? "Responsabilidade e contato" : code === "ja" ? "責任と連絡先" : "책임 및 연락처"}</h2>
    <p>${code === "he" ? "השירות מסופק כפי שהוא. לשאלות תמיכה, משפטיות או פרטיות השתמש בטופס התמיכה; לבקשות נפח סריקות גדול יותר השתמש בטופס המכירות." : code === "de" ? "Der Dienst wird wie besehen bereitgestellt. Fuer Support, Recht oder Datenschutz nutzen Sie das Support-Formular; fuer hoeheres Scan-Volumen das Sales-Formular." : code === "fr" ? "Le service est fourni tel quel. Pour support, juridique ou confidentialite utilisez le formulaire support; pour un volume de scans plus eleve le formulaire sales." : code === "pt" ? "O servico e fornecido como esta. Para suporte, legal ou privacidade use o formulario de suporte; para maior volume de scans use vendas." : code === "ja" ? "本サービスは現状有姿で提供されます。サポート、法務、プライバシーはサポートフォームへ、追加スキャン量は営業フォームへお問い合わせください。" : "서비스는 있는 그대로 제공됩니다. 지원, 법무, 개인정보 문의는 지원 양식으로, 추가 스캔 용량 문의는 영업 양식으로 보내세요."}</p>`;
}

Object.assign(STATIC_T.de, {
  skill_f1: "Prompt-Injection-Erkennung", skill_f1d: "Erkennt versteckte Anweisungen, Jailbreaks und Prompt-Override-Versuche.",
  skill_f2: "Rollenverwirrung", skill_f2d: "Erkennt Skills, die der KI eine andere Identitat aufzwingen wollen.",
  skill_f3: "Versteckte Payloads", skill_f3d: "Findet Base64-, Unicode- und Zero-Width-Verschleierung.",
  ext_f1: "Credential-Diebstahl", ext_f1d: "Erkennt Code, der SSH-Keys, npm-Tokens, AWS-Credentials und Secrets liest.",
  ext_f2: "Datenabfluss", ext_f2d: "Findet Netzwerkaufrufe, die Code oder Dateien an externe Server senden.",
  ext_f3: "Supply-Chain-Angriffe", ext_f3d: "Erkennt Typosquatting, Dependency Confusion und riskante Install-Skripte."
});
Object.assign(STATIC_T.fr, {
  skill_f1: "Detection de prompt injection", skill_f1d: "Detecte instructions cachees, jailbreaks et tentatives de contournement.",
  skill_f2: "Confusion de role", skill_f2d: "Detecte les skills qui tentent de changer l'identite de l'IA.",
  skill_f3: "Charges cachees", skill_f3d: "Repere l'obfuscation Base64, Unicode et caracteres invisibles.",
  ext_f1: "Vol d'identifiants", ext_f1d: "Detecte la lecture de cles SSH, tokens npm, credentials AWS et secrets.",
  ext_f2: "Exfiltration de donnees", ext_f2d: "Repere les appels reseau envoyant code ou fichiers vers des serveurs externes.",
  ext_f3: "Attaques supply chain", ext_f3d: "Detecte typosquatting, dependency confusion et scripts d'installation risques."
});
Object.assign(STATIC_T.pt, {
  skill_f1: "Deteccao de prompt injection", skill_f1d: "Detecta instrucoes ocultas, jailbreaks e tentativas de sobrescrever prompts.",
  skill_f2: "Confusao de papel", skill_f2d: "Detecta skills que tentam fazer a IA assumir outra identidade.",
  skill_f3: "Payloads ocultos", skill_f3d: "Encontra ofuscacao Base64, Unicode e caracteres invisiveis.",
  ext_f1: "Roubo de credenciais", ext_f1d: "Detecta leitura de chaves SSH, tokens npm, credenciais AWS e segredos.",
  ext_f2: "Exfiltracao de dados", ext_f2d: "Encontra chamadas de rede que enviam codigo ou arquivos para servidores externos.",
  ext_f3: "Ataques de supply chain", ext_f3d: "Detecta typosquatting, dependency confusion e scripts de instalacao arriscados."
});
Object.assign(STATIC_T.ja, {
  skills_sub: "Claude Skills、Cursor Skills、カスタムプロンプトには、隠れたプロンプトインジェクションや悪意ある処理が含まれる可能性があります。",
  skill_f1: "プロンプトインジェクション検出", skill_f1d: "隠れた命令、Jailbreak、プロンプト上書きの試みを検出します。",
  skill_f2: "役割の混乱", skill_f2d: "AI に別の役割や身元を強制しようとする Skill を検出します。",
  skill_f3: "隠れたペイロード", skill_f3d: "Base64、Unicode、ゼロ幅文字による難読化を見つけます。",
  need_mcp: "MCP スキャンも必要ですか？", need_mcp_sub: "同じスキャナー、同じアカウントで MCP も完全にカバーします。", mcp_scanner: "MCP セキュリティスキャナー",
  ext_sub: "VS Code、Cursor、JetBrains 拡張はファイルを読めます。悪意ある拡張は認証情報やソースコードを盗む可能性があります。",
  ext_incident_t: "重要な理由", ext_incident_d: "開発者向け拡張は広い権限で動作し、API キー、ソースコード、SSH 認証情報を盗む可能性があります。",
  ext_f1: "認証情報の窃取", ext_f1d: "SSH キー、npm トークン、AWS 認証情報、環境変数の読み取りを検出します。",
  ext_f2: "データ流出", ext_f2d: "コードやファイルを外部サーバーへ送信する通信を見つけます。",
  ext_f3: "サプライチェーン攻撃", ext_f3d: "タイポスクワッティング、依存関係混乱、危険なインストールスクリプトを検出します。"
});
Object.assign(STATIC_T.ko, {
  skills_sub: "Claude Skills, Cursor Skills 및 사용자 프롬프트에는 숨겨진 프롬프트 인젝션이나 악성 페이로드가 포함될 수 있습니다.",
  skill_f1: "프롬프트 인젝션 탐지", skill_f1d: "숨겨진 지시, jailbreak 및 프롬프트 우회 시도를 탐지합니다.",
  skill_f2: "역할 혼동", skill_f2d: "AI가 다른 정체성을 갖도록 유도하는 Skill을 탐지합니다.",
  skill_f3: "숨겨진 페이로드", skill_f3d: "Base64, Unicode 및 zero-width 문자 난독화를 찾습니다.",
  need_mcp: "MCP 스캔도 필요하신가요?", need_mcp_sub: "같은 스캐너와 계정으로 MCP도 완전히 커버합니다.", mcp_scanner: "MCP 보안 스캐너",
  ext_sub: "VS Code, Cursor, JetBrains 확장은 파일을 읽을 수 있습니다. 악성 확장은 자격 증명과 소스 코드를 유출할 수 있습니다.",
  ext_incident_t: "중요한 이유", ext_incident_d: "개발자 확장은 넓은 권한으로 실행되며 API 키, 소스 코드, SSH 자격 증명을 훔칠 수 있습니다.",
  ext_f1: "자격 증명 탈취", ext_f1d: "SSH 키, npm 토큰, AWS 자격 증명 및 환경 비밀 읽기를 탐지합니다.",
  ext_f2: "데이터 유출", ext_f2d: "코드나 파일을 외부 서버로 보내는 네트워크 호출을 찾습니다.",
  ext_f3: "공급망 공격", ext_f3d: "타이포스쿼팅, dependency confusion 및 위험한 설치 스크립트를 탐지합니다."
});

function getStaticLang() {
  const saved = localStorage.getItem("cg-lang");
  if (saved && STATIC_T[saved]) return saved;
  const browser = (navigator.language || "en").toLowerCase().split("-")[0];
  return STATIC_T[browser] ? browser : "en";
}

function staticText(key) {
  const lang = getStaticLang();
  return String(STATIC_T[lang]?.[key] || STATIC_T.en[key] || key).replace(/^\/\/\s*/, "");
}

const CONTACT_ACCESS_COPY = {
  en: {
    contact_sub: "Use this form for larger scan-volume requests, procurement questions, support, or security issues. Your message stays inside the site and goes to the right inbox.",
    opt_sales: "Large-volume request",
    opt_enterprise: "Organization / procurement",
    contact_direct: "Large-volume and business requests go to sales@cyberguardianscan.com. Support and security requests go to support@cyberguardianscan.com."
  },
  he: {
    contact_sub: "השתמשו בטופס לבקשות נפח סריקות גדול יותר, רכש, תמיכה או שאלות אבטחה. ההודעה נשארת באתר ומנותבת לתיבה הנכונה.",
    opt_sales: "בקשת נפח סריקות גדול",
    opt_enterprise: "ארגון / רכש",
    contact_direct: "בקשות לנפח סריקות גדול ולפניות עסקיות מנותבות אל sales@cyberguardianscan.com. תמיכה ואבטחה מנותבות אל support@cyberguardianscan.com."
  },
  de: {
    contact_sub: "Nutzen Sie dieses Formular fuer hoehere Scan-Volumen, Einkauf, Support oder Sicherheitsfragen.",
    opt_sales: "Hoeheres Scan-Volumen",
    opt_enterprise: "Organisation / Einkauf",
    contact_direct: "Anfragen zu hoeherem Scan-Volumen gehen an sales@cyberguardianscan.com. Support und Sicherheit gehen an support@cyberguardianscan.com."
  },
  ja: {
    contact_sub: "スキャン量の追加、購買、サポート、セキュリティ質問はこちらから送信できます。",
    opt_sales: "追加スキャン量の相談",
    opt_enterprise: "組織 / 購買",
    contact_direct: "追加スキャン量やビジネス相談は sales@cyberguardianscan.com へ、サポートとセキュリティは support@cyberguardianscan.com へ送られます。"
  },
  ko: {
    contact_sub: "더 많은 스캔 용량, 구매, 지원 또는 보안 질문을 이 양식으로 보내세요.",
    opt_sales: "추가 스캔 용량 문의",
    opt_enterprise: "조직 / 구매",
    contact_direct: "추가 스캔 용량 및 비즈니스 문의는 sales@cyberguardianscan.com 으로, 지원 및 보안 문의는 support@cyberguardianscan.com 으로 전달됩니다."
  },
  fr: {
    contact_sub: "Utilisez ce formulaire pour un volume de scans plus eleve, achat, support ou questions securite.",
    opt_sales: "Volume de scans plus eleve",
    opt_enterprise: "Organisation / achat",
    contact_direct: "Les demandes de volume plus eleve vont a sales@cyberguardianscan.com. Support et securite vont a support@cyberguardianscan.com."
  },
  pt: {
    contact_sub: "Use este formulario para maior volume de scans, compras, suporte ou seguranca.",
    opt_sales: "Maior volume de scans",
    opt_enterprise: "Organizacao / compras",
    contact_direct: "Pedidos de maior volume vao para sales@cyberguardianscan.com. Suporte e seguranca vao para support@cyberguardianscan.com."
  }
};

Object.entries(CONTACT_ACCESS_COPY).forEach(([lang, copy]) => {
  STATIC_T[lang] = { ...(STATIC_T[lang] || {}), ...copy };
});

function setStaticLang(code) {
  if (!STATIC_T[code]) return;
  localStorage.setItem("cg-lang", code);
  document.documentElement.lang = code;
  document.documentElement.dir = STATIC_LANGS[code].dir;
  applyPageSpecificStaticTranslations();
  document.querySelectorAll("[data-static-i18n]").forEach(el => {
    el.textContent = staticText(el.getAttribute("data-static-i18n"));
  });
  document.querySelectorAll("[data-static-i18n-html]").forEach(el => {
    el.innerHTML = staticText(el.getAttribute("data-static-i18n-html"));
  });
  document.querySelectorAll("[data-static-placeholder]").forEach(el => {
    el.placeholder = staticText(el.getAttribute("data-static-placeholder"));
  });
  document.querySelectorAll("[data-static-value]").forEach(el => {
    el.textContent = staticText(el.getAttribute("data-static-value"));
  });
  document.querySelectorAll(".static-lang-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.lang === code);
  });
}

function buildStaticLangSwitcher() {
  let container = document.getElementById("static-lang-switcher");
  if (!container) {
    const nav = document.querySelector("nav");
    if (!nav) return;
    container = document.createElement("div");
    container.id = "static-lang-switcher";
    container.className = "static-lang-switcher";
    const lastLink = nav.querySelector("a:last-child");
    if (lastLink) nav.insertBefore(container, lastLink);
    else nav.appendChild(container);
  }
  if (!container) return;
  container.innerHTML = "";
  Object.entries(STATIC_LANGS).forEach(([code, info]) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "static-lang-btn";
    btn.dataset.lang = code;
    btn.title = info.flag;
    btn.setAttribute("aria-label", info.flag);
    const flag = document.createElement("span");
    flag.className = `static-flag-icon static-flag-${info.flagCode}`;
    flag.setAttribute("aria-hidden", "true");
    btn.appendChild(flag);
    btn.onclick = () => setStaticLang(code);
    container.appendChild(btn);
  });
}

function setText(selector, key) {
  const el = document.querySelector(selector);
  if (el) el.textContent = staticText(key);
}

function setHtml(selector, key) {
  const el = document.querySelector(selector);
  if (el) el.innerHTML = staticText(key);
}

function applyLegalBody(kind) {
  const wrap = document.querySelector(".wrap");
  const header = document.querySelector("header");
  const footer = document.querySelector("footer");
  if (!wrap || !header || !footer) return;
  [...wrap.children].forEach(child => {
    if (child !== header && child !== footer) child.remove();
  });
  const content = document.createElement("div");
  content.innerHTML = staticText(kind === "privacy" ? "privacy_body" : "terms_body");
  wrap.insertBefore(content, footer);
}

function applyPageSpecificStaticTranslations() {
  const path = location.pathname;
  if (path.endsWith("/skills.html")) {
    setText(".back-link", "back_scanner");
    setText(".eyebrow", "skills_eyebrow");
    setText(".hero h1", "skills_title");
    setText(".hero-sub", "skills_sub");
    setText(".hero .cta-btn", "open_scanner");
    setText(".feat:nth-child(1) .feat-t", "skill_f1");
    setText(".feat:nth-child(1) .feat-d", "skill_f1d");
    setText(".feat:nth-child(2) .feat-t", "skill_f2");
    setText(".feat:nth-child(2) .feat-d", "skill_f2d");
    setText(".feat:nth-child(3) .feat-t", "skill_f3");
    setText(".feat:nth-child(3) .feat-d", "skill_f3d");
    setText(".lower-cta-title", "need_mcp");
    setText(".lower-cta-sub", "need_mcp_sub");
    setText(".lower-cta .cta-btn", "mcp_scanner");
  }
  if (path.endsWith("/extensions.html")) {
    setText(".back-link", "back_scanner");
    setText(".eyebrow", "ext_eyebrow");
    setText(".hero h1", "ext_title");
    setText(".hero-sub", "ext_sub");
    setText(".hero .cta-btn", "open_scanner");
    setText(".real-incident-t", "ext_incident_t");
    setText(".real-incident-d", "ext_incident_d");
    setText(".feat:nth-child(1) .feat-t", "ext_f1");
    setText(".feat:nth-child(1) .feat-d", "ext_f1d");
    setText(".feat:nth-child(2) .feat-t", "ext_f2");
    setText(".feat:nth-child(2) .feat-d", "ext_f2d");
    setText(".feat:nth-child(3) .feat-t", "ext_f3");
    setText(".feat:nth-child(3) .feat-d", "ext_f3d");
    setText(".lower-cta-title", "need_mcp");
    setText(".lower-cta-sub", "need_mcp_sub");
    setText(".lower-cta .cta-btn", "mcp_scanner");
  }
  if (path.endsWith("/privacy.html")) {
    setText(".back", "back_scanner");
    setText("h1", "privacy_title");
    setText(".updated", "updated");
    applyLegalBody("privacy");
  }
  if (path.endsWith("/terms.html")) {
    setText(".back", "back_scanner");
    setText("h1", "terms_title");
    setText(".updated", "updated");
    applyLegalBody("terms");
  }
}

const style = document.createElement("style");
style.textContent = ".static-lang-switcher{display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end;align-items:center}.static-lang-btn{min-width:44px;min-height:30px;display:inline-flex;align-items:center;justify-content:center;background:#1E2D3D;border:1px solid #2A3F54;color:#7A9BB0;padding:5px 9px;font-size:15px;border-radius:4px;cursor:pointer;font-family:var(--mono,'IBM Plex Mono',Consolas,monospace);letter-spacing:1px;transition:all .15s;line-height:1}.static-lang-btn:hover{border-color:#00D4FF;background:#243346;color:#00D4FF;transform:scale(1.08)}.static-lang-btn.active{border-color:#00D4FF;background:rgba(0,212,255,.18);color:#00D4FF;font-weight:700;box-shadow:0 0 10px rgba(0,212,255,.35)}.static-flag-icon{position:relative;display:block;width:24px;height:16px;overflow:hidden;border-radius:2px;background:#fff;box-shadow:inset 0 0 0 1px rgba(255,255,255,.28),0 0 0 1px rgba(0,0,0,.25)}.static-flag-us{background:repeating-linear-gradient(to bottom,#b22234 0 1.23px,#fff 1.23px 2.46px)}.static-flag-us:before{content:'';position:absolute;left:0;top:0;width:10px;height:8.6px;background:#3c3b6e}.static-flag-il{background:linear-gradient(to bottom,#fff 0 16%,#005eb8 16% 28%,#fff 28% 72%,#005eb8 72% 84%,#fff 84%)}.static-flag-il:before{content:'✡';position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#005eb8;font-size:8px;line-height:1}.static-flag-de{background:linear-gradient(to bottom,#000 0 33.33%,#dd0000 33.33% 66.66%,#ffce00 66.66%)}.static-flag-jp:before{content:'';position:absolute;width:8px;height:8px;border-radius:50%;background:#bc002d;left:50%;top:50%;transform:translate(-50%,-50%)}.static-flag-kr:before{content:'';position:absolute;width:9px;height:9px;border-radius:50%;background:linear-gradient(to bottom,#cd2e3a 0 50%,#0047a0 50%);left:50%;top:50%;transform:translate(-50%,-50%) rotate(28deg)}.static-flag-fr{background:linear-gradient(to right,#0055a4 0 33.33%,#fff 33.33% 66.66%,#ef4135 66.66%)}.static-flag-br{background:#009b3a}.static-flag-br:before{content:'';position:absolute;width:13px;height:13px;background:#ffdf00;left:50%;top:50%;transform:translate(-50%,-50%) rotate(45deg)}.static-flag-br:after{content:'';position:absolute;width:7px;height:7px;border-radius:50%;background:#002776;left:50%;top:50%;transform:translate(-50%,-50%)}";
document.head.appendChild(style);

buildStaticLangSwitcher();
setStaticLang(getStaticLang());

window.staticText = staticText;
window.setStaticLang = setStaticLang;
