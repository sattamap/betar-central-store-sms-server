/* const fs = require("fs");
const path = require("path");
const puppeteer = require("puppeteer");

const enToBnDigits = (input) => {
  const enDigits = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
  const bnDigits = ["০", "১", "২", "৩", "৪", "৫", "৬", "৭", "৮", "৯"];
  return input.toString().split("").map(char => {
    const index = enDigits.indexOf(char);
    return index !== -1 ? bnDigits[index] : char;
  }).join("");
};

const generateItemPDF = async (records) => {
  const htmlPath = path.join(__dirname, "../templates/recordTemplates.html");
  let html = fs.readFileSync(htmlPath, "utf-8");

  const tableRows = records
    .map(
      (item, index) => `
      <tr>
        <td>${enToBnDigits(index + 1)}</td>
        <td>
          <strong>${item.itemName}</strong><br/>
          Model: ${item.model || "-"}<br/>
          Category: ${item.category || "-"}
        </td>
        <td>${enToBnDigits(item?.items_quantity?.item_store ?? 0)}</td>
        <td>${enToBnDigits(item?.items_quantity?.item_use ?? 0)}</td>
        <td>${enToBnDigits(item?.items_quantity?.item_faulty_store ?? 0)}</td>
        <td>${enToBnDigits(item?.items_quantity?.item_faulty_use ?? 0)}</td>
        <td>${enToBnDigits(item?.items_quantity?.item_transfer ?? 0)}</td>
        <td>${item.locationGood || "-"}</td>
        <td>${item.purpose || "-"}</td>
        <td>${item.date || "-"}</td>
        <td>${item.status || "-"}</td>
      </tr>`
    )
    .join("");

  html = html.replace(
    '<tbody id="table-body"></tbody>',
    `<tbody id="table-body">${tableRows}</tbody>`
  );

  const browser = await puppeteer.launch({
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });

  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: "networkidle0" });

  const pdfBuffer = await page.pdf({
    format: "A4",
    printBackground: true,
    landscape: true,
  });

  await browser.close();
  return pdfBuffer;
};

module.exports = generateItemPDF;
 */



/* const puppeteer = require("puppeteer");

// Convert English digits → Bangla digits
const enToBnDigits = (input) => {
  const enDigits = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
  const bnDigits = ["০", "১", "২", "৩", "৪", "৫", "৬", "৭", "৮", "৯"];
  return input
    ?.toString()
    .split("")
    .map((char) => {
      const index = enDigits.indexOf(char);
      return index !== -1 ? bnDigits[index] : char;
    })
    .join("");
};

const generateRecordPDF = async (records) => {
  // Inline HTML template
  let html = `
  <!DOCTYPE html>
  <html lang="bn">
  <head>
    <meta charset="UTF-8" />
    <title>Records Report</title>
    <style>
      body {
        font-family: Arial, sans-serif;
        font-size: 11px;
        padding: 20px;
      }

      h1 {
        text-align: center;
        margin-bottom: 20px;
      }

      table {
        width: 100%;
        border-collapse: collapse;
        table-layout: fixed;
      }

      th, td {
        border: 1px solid #333;
        padding: 4px;
        text-align: left;
        word-wrap: break-word;
      }

      th {
        background-color: #eee;
      }

      strong {
        font-weight: bold;
      }
    </style>
  </head>
  <body>
    <h1>রেকর্ড রিপোর্ট</h1>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>নাম, মডেল & উৎপত্তি</th>
          <th>পণ্য (স্টোর)</th>
          <th>পণ্য (ব্যবহার)</th>
          <th>পণ্য (স্টোরে নষ্ট)</th>
          <th>পণ্য (ব্যবহারে নষ্ট)</th>
          <th>পণ্য (আন্তঃকেন্দ্রীক বদলী)</th>
          <th>স্থান</th>
          <th>উদ্দেশ্য</th>
          <th>সময়</th>
          <th>স্ট্যাটাস</th>
        </tr>
      </thead>
      <tbody id="table-body"></tbody>
    </table>
  </body>
  </html>
  `;

  // Insert rows
  const tableRows = records
    .map(
      (item, index) => `
      <tr>
        <td>${enToBnDigits(index + 1)}</td>
        <td>
          <strong>${item.itemName}</strong><br/>
          মডেল: ${item.model || "-"}<br/>
          ক্যাটাগরি: ${item.category || "-"}
        </td>
        <td>${enToBnDigits(item?.items_quantity?.item_store ?? 0)}</td>
        <td>${enToBnDigits(item?.items_quantity?.item_use ?? 0)}</td>
        <td>${enToBnDigits(item?.items_quantity?.item_faulty_store ?? 0)}</td>
        <td>${enToBnDigits(item?.items_quantity?.item_faulty_use ?? 0)}</td>
        <td>${enToBnDigits(item?.items_quantity?.item_transfer ?? 0)}</td>
        <td>${item.locationGood || "-"}</td>
        <td>${item.purpose || "-"}</td>
        <td>${item.date || "-"}</td>
        <td>${item.status || "-"}</td>
      </tr>`
    )
    .join("");

  html = html.replace(
    '<tbody id="table-body"></tbody>',
    `<tbody id="table-body">${tableRows}</tbody>`
  );

  // Puppeteer launch for serverless
  const browser = await puppeteer.launch({
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
    headless: "new",
  });

  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: "networkidle0" });

  const pdfBuffer = await page.pdf({
    format: "A4",
    printBackground: true,
    landscape: true,
  });

  await browser.close();
  return pdfBuffer;
};

module.exports = generateRecordPDF;
 */



const fs = require("fs");
const path = require("path");

const isProd = process.env.NODE_ENV === "production";
const puppeteer = isProd ? require("puppeteer-core") : require("puppeteer");
const chromium = isProd ? require("@sparticuz/chromium") : null;

// Load Bangla font as base64
const fontPath = path.join(__dirname, "../fonts/TiroBangla-Regular.ttf");
const banglaFontBase64 = fs.readFileSync(fontPath).toString("base64");

// Convert English digits → Bangla digits
const enToBnDigits = (input) => {
  const enDigits = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
  const bnDigits = ["০", "১", "২", "৩", "৪", "৫", "৬", "৭", "৮", "৯"];
  return input?.toString().split("").map(c => {
    const idx = enDigits.indexOf(c);
    return idx !== -1 ? bnDigits[idx] : c;
  }).join("");
};

// Format date YYYY-MM-DD → DD-MM-YY (Bangla)
const formatBnDate = (dateStr) => {
  if (!dateStr) return "-";

  const [year, month, day] = dateStr.split("-");
  const shortYear = year.slice(-2); // last 2 digits

  return enToBnDigits(`${day}-${month}-${shortYear}`);
};


const generateRecordPDF = async (records) => {
  let html = `
  <!DOCTYPE html>
  <html lang="bn">
  <head>
    <meta charset="UTF-8" />
    <title>রেকর্ড রিপোর্ট</title>
    <style>
      @font-face {
        font-family: "TiroBangla";
        src: url(data:font/ttf;base64,${banglaFontBase64}) format("truetype");
        font-weight: normal;
        font-style: normal;
      }

      @page {
        size: A4 landscape;
        margin: 30px 20px;
      }

      body { font-family: "TiroBangla", sans-serif; font-size: 11px; padding: 20px; }
      h1 { text-align: center; margin-bottom: 20px; }
      table { width: 100%; border-collapse: collapse; table-layout: fixed; }
      th, td { border: 1px solid #333; padding: 4px; text-align: left; word-wrap: break-word; }
      th { background-color: #eee; }
      strong { font-weight: bold; }
    </style>
  </head>
  <body>
    <h1>রেকর্ড রিপোর্ট</h1>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>নাম, মডেল & ক্যাটাগরি</th>
          <th>পণ্য (স্টোর)</th>
          <th>পণ্য (ব্যবহার)</th>
          <th>পণ্য (স্টোরে নষ্ট)</th>
          <th>পণ্য (ব্যবহারে নষ্ট)</th>
          <th>পণ্য (আন্তঃকেন্দ্রীক বদলী)</th>
          <th>স্থান</th>
          <th>উদ্দেশ্য</th>
          <th>সময়</th>
          <th>সম্পৃক্ত ব্যক্তিবর্গ</th>
        </tr>
      </thead>
      <tbody id="table-body"></tbody>
    </table>
  </body>
  </html>
  `;
const tableRows = records.map((item, index) => `
  <tr>
    <td>${enToBnDigits(index + 1)}</td>

    <td>
      <strong>${item.itemName}</strong><br/>
      মডেল: ${item.model || "-"}<br/>
      ক্যাটাগরি: ${item.category || "-"}
    </td>

    <td>${enToBnDigits(item?.items_quantity?.item_store ?? 0)}</td>
    <td>${enToBnDigits(item?.items_quantity?.item_use ?? 0)}</td>
    <td>${enToBnDigits(item?.items_quantity?.item_faulty_store ?? 0)}</td>
    <td>${enToBnDigits(item?.items_quantity?.item_faulty_use ?? 0)}</td>
    <td>${enToBnDigits(item?.items_quantity?.item_transfer ?? 0)}</td>

    <td>${item.locationGood || "-"}</td>
    <td>${item.purpose || "-"}</td>
    <td>${item.date ? formatBnDate(item.date) : "-"}</td>

    <!-- Participants column -->
    <td style="font-size:11px; line-height:1.4">
      ${
        item.requestedBy?.name
          ? `<div><strong>চাহিদাকারী:</strong><br/>${item.requestedBy.name}</div>`
          : ""
      }
      ${
        item.forwardedBy?.name
          ? `<div><strong>স্টোরকিপার:</strong><br/>${item.forwardedBy.name}</div>`
          : ""
      }
      ${
        item.finalApprovedBy?.name
          ? `<div><strong>অনুমোদনকারী:</strong><br/>${item.finalApprovedBy.name}</div>`
          : ""
      }
      ${
        item.acceptedBy?.name
          ? `<div style="color:green;font-weight:bold">✔ গ্রহণকারী:<br/>${item.acceptedBy.name}</div>`
          : ""
      }
      ${
        !item.requestedBy &&
        !item.forwardedBy &&
        !item.finalApprovedBy &&
        !item.acceptedBy
          ? `<div style="color:#999;font-style:italic">তথ্য নেই</div>`
          : ""
      }
    </td>
  </tr>
`).join("");


  html = html.replace('<tbody id="table-body"></tbody>', `<tbody id="table-body">${tableRows}</tbody>`);

  // Puppeteer launch
  const browser = await puppeteer.launch({
    args: chromium ? chromium.args : ["--no-sandbox", "--disable-setuid-sandbox"],
    defaultViewport: chromium ? chromium.defaultViewport : null,
    executablePath: isProd ? await chromium.executablePath() : undefined,
    headless: chromium ? chromium.headless : true,
  });

  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: "networkidle0" });

  const pdfBuffer = await page.pdf({
    format: "A4",
    printBackground: true,
    landscape: true,
  });

  await browser.close();
  return pdfBuffer;
};

module.exports = generateRecordPDF;
