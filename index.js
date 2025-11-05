const express = require("express");
require("dotenv").config();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const { MongoClient, ServerApiVersion, ObjectId, Double } = require("mongodb");

function isValidObjectId(id) {
  if (!ObjectId.isValid(id)) return false;

  // Convert and check if the resulting id string matches the original
  try {
    const objectId = ObjectId.createFromHexString(id);
    return objectId.toHexString() === id;
  } catch {
    return false;
  }
}

const generateServicePDF = require("./utils/generateServicePDF");
const generateItemPDF = require("./utils/generateItemPDF");
const generateRecordPDF = require("./utils/generateRecordPDF");
const generateNotificationPDF = require("./utils/generateNotificationPDF");

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(
  cors({
    origin: [
      "https://bbsms-5a136.web.app", // Live site (Firebase Hosting)
      "https://bbsms-5a136.firebaseapp.com", // Firebase fallback domain
      "http://localhost:5173",
      "http://localhost:5174",
    ],
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

const verifyToken = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) return res.status(401).send({ message: "Unauthorized" });

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).send({ message: "TokenExpired" });
      }
      return res.status(403).send({ message: "Forbidden" });
    }
    req.user = decoded;
    next();
  });
};

app.post("/api/generate-pdf", async (req, res) => {
  try {
    const { data, type = "services", filename = "report" } = req.body;

    if (!data || !Array.isArray(data) || data.length === 0) {
      return res.status(400).send("Invalid or empty data provided.");
    }

    let pdfBuffer;

    if (type === "services") {
      pdfBuffer = await generateServicePDF(data);
    } else if (type === "items") {
      pdfBuffer = await generateItemPDF(data);
    } else if (type === "records") {
      pdfBuffer = await generateRecordPDF(data); // ✅ new handler
    } else if (type === "notifications") {
      pdfBuffer = await generateNotificationPDF(data); // ✅ new handler
    } else {
      return res.status(400).send("Invalid PDF type.");
    }

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=${filename}.pdf`
    );

    return res.end(pdfBuffer);
  } catch (error) {
    console.error("PDF generation error:", error);
    return res.status(500).send("Failed to generate PDF");
  }
});

// MongoDB connection URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.zn9p2it.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let dbMap = {};

async function connectDatabases() {
  //await client.connect();
  dbMap["head-items"] = client.db("sms-head-items");
  dbMap["local-items"] = client.db("sms-local-items");
  dbMap["head-services"] = client.db("sms-head-services");
  dbMap["local-services"] = client.db("sms-local-services");
  dbMap["main"] = client.db("sms-main");
  console.log("✅ Connected to all SMS databases");
}

function getDB(block) {
  return dbMap[block];
}

function createRoutesForBlock(block) {
  const itemsDB = getDB(`${block}-items`);
  const servicesDB = getDB(`${block}-services`);
  const prefix = `/${block}`;

  const itemsCollection = itemsDB.collection("items");
  const servicesCollection = servicesDB.collection("services");
  const recordsCollection = itemsDB.collection("records");

  // Generate JWT token
  app.post("/jwt", (req, res) => {
    const user = req.body;
    const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
      expiresIn: "2h",
    });

    res
      .cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
      })
      .send({ success: true });
  });

  // Clear JWT cookie
  app.post("/logout", (req, res) => {
    res
      .clearCookie("token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
        path: "/",
      })
      .send({ success: true });
  });

  app.get(`${prefix}/items`, verifyToken, async (req, res) => {
    try {
      const items = await itemsCollection.find({}).toArray();
      res.send(items);
    } catch (error) {
      console.error(`Error in ${prefix}/items/all:`, error);
      res.status(500).send({ error: "Failed to fetch all items" });
    }
  });

  // 🔒 GET item by ID (protected)
  app.get(`${prefix}/items/:id`, async (req, res) => {
    const { id } = req.params;

    if (!id || id.length !== 24) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    const _id = new ObjectId(id);
    const result = await itemsCollection.findOne({ _id });
    res.send(result);
  });

  // 🔒 GET item by model (protected)
  app.get(`${prefix}/items/model/:model`, verifyToken, async (req, res) => {
    const result = await itemsCollection.findOne({ model: req.params.model });
    res.send(result);
  });

app.post(`${prefix}/item`, verifyToken, async (req, res) => {
  const newItem = req.body;
  const existing = await itemsCollection.findOne({ model: newItem.model });

  if (existing) {
    return res
      .status(400)
      .json({ success: false, message: "Model already exists." });
  }

  // 🔧 Ensure all numeric quantities are stored as Double
  if (newItem.items_quantity) {
    newItem.items_quantity.item_store = new Double(newItem.items_quantity.item_store || 0);
    newItem.items_quantity.item_use = new Double(newItem.items_quantity.item_use || 0);
    newItem.items_quantity.item_faulty_store = new Double(newItem.items_quantity.item_faulty_store || 0);
    newItem.items_quantity.item_faulty_use = new Double(newItem.items_quantity.item_faulty_use || 0);
    newItem.items_quantity.item_transfer = new Double(newItem.items_quantity.item_transfer || 0);
  }

  newItem.totalQuantity = new Double(newItem.totalQuantity || 0);

  const result = await itemsCollection.insertOne(newItem);

  // ✅ Notification
  const notificationsCollection = dbMap["main"].collection("notifications");
  await notificationsCollection.insertOne({
    type: "item_added",
    module: "items",
    message: `Admin/Coordinator ${req.user.email} added "${newItem.itemName}" (${newItem.model}) in ${block.toUpperCase()} block.`,
    timestamp: new Date(),
    seen: false,
    block,
  });

  res.json({ success: true, insertedId: result.insertedId });
});

  // 🔒 Update item (PATCH)
  app.patch(`${prefix}/items/:id`, verifyToken, async (req, res) => {
    const { id } = req.params;

    // ✅ Validate ObjectId format
    if (!id || id.length !== 24) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    try {
      const _id = new ObjectId(id);
      const result = await itemsCollection.updateOne(
        { _id },
        { $set: req.body }
      );

      // ✅ Notify Admin after successful update
      const updatedItem = req.body;
      const notificationsCollection = dbMap["main"].collection("notifications");
      await notificationsCollection.insertOne({
        type: "item_updated",
        module: "items",
        message: `Admin/Coordinator ${req.user.email} updated "${
          updatedItem.itemName
        }" (${updatedItem.model}) in ${block.toUpperCase()} block.`,
        timestamp: new Date(),
        seen: false,
        block,
      });

      res.send(result);
    } catch (error) {
      console.error("Update error:", error);
      res.status(500).json({ message: "Something went wrong" });
    }
  });

  // 🔒 Delete item (DELETE)
  app.delete(`${prefix}/item/:itemId`, verifyToken, async (req, res) => {
    const { itemId } = req.params;

    // ✅ Validate ObjectId format
    if (!itemId || itemId.length !== 24) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    try {
      const _id = new ObjectId(itemId);
      const result = await itemsCollection.deleteOne({ _id });

      if (result.deletedCount === 0) {
        return res.status(404).json({ message: "Item not found" });
      }

      res.send(result);
    } catch (error) {
      console.error("Delete error:", error);
      res.status(500).json({ message: "Something went wrong" });
    }
  });

  app.post(`${prefix}/service`, verifyToken, async (req, res) => {
    const newService = req.body;

    try {
      const existing = await servicesCollection.findOne({
        serviceName: newService.serviceName,
      });

      if (existing) {
        return res.status(400).json({
          success: false,
          message: "Service with this name already exists.",
        });
      }

      const result = await servicesCollection.insertOne(newService);
      const notificationsCollection = dbMap["main"].collection("notifications");
      await notificationsCollection.insertOne({
        type: "service_added",
        module: "services",
        message: `Admin/Coordinator ${req.user.email} added new service "${
          newService.serviceName
        }" in ${block.toUpperCase()} block.`,
        timestamp: new Date(),
        seen: false,
        block,
      });

      res.json({ success: true, insertedId: result.insertedId });
    } catch (error) {
      res
        .status(500)
        .send({ success: false, message: "Failed to add service" });
    }
  });

  app.get(`${prefix}/services`, verifyToken, async (req, res) => {
    try {
      const services = await servicesCollection.find({}).toArray();
      res.send(services);
    } catch (error) {
      res.status(500).send({ error: "Failed to fetch services" });
    }
  });

  app.get(`${prefix}/services/:id`, verifyToken, async (req, res) => {
    try {
      const service = await servicesCollection.findOne({
        _id: new ObjectId(req.params.id),
      });
      if (!service) {
        return res.status(404).send({ message: "Service not found" });
      }
      res.send(service);
    } catch (error) {
      res.status(500).send({ message: "Failed to fetch service" });
    }
  });

  // ✅ Get single service by ID
  app.patch(`${prefix}/services/:id`, verifyToken, async (req, res) => {
    try {
      const { _id, ...updateData } = req.body; // ✅ Remove _id from update

      const result = await servicesCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: updateData }
      );

      if (result.modifiedCount > 0) {
        // ✅ Auto-notify Admin after service update
        const notificationsCollection =
          dbMap["main"].collection("notifications");
        await notificationsCollection.insertOne({
          type: "service_updated",
          module: "services",
          message: `Admin/Coordinator ${req.user.email} updated "${
            updateData.serviceName
          }" in ${block.toUpperCase()} block.`,
          timestamp: new Date(),
          seen: false,
          block,
        });
      }

      res.send(result);
    } catch (error) {
      console.error("Update error:", error);
      res.status(500).send({ message: "Failed to update service" });
    }
  });

  // ✅ Delete service by ID (for your ManageServices.jsx)
  app.delete(`${prefix}/services/:id`, verifyToken, async (req, res) => {
    try {
      const result = await servicesCollection.deleteOne({
        _id: new ObjectId(req.params.id),
      });
      res.send(result);
    } catch (error) {
      res.status(500).send({ message: "Failed to delete service" });
    }
  });

  // 🔒 GET records
  app.get(`${prefix}/records`, verifyToken, async (req, res) => {
    const result = await recordsCollection.find().toArray();
    res.send(result);
  });

  // 🔒 Create a new record
app.post(`${prefix}/records`, verifyToken, async (req, res) => {
  try {
    const {
      itemName,
      model,
      category,
      date,
      status,
      itemId,
      items_quantity = {},
      purpose,
      locationGood,
    } = req.body;

    if (!isValidObjectId(itemId)) {
      return res.status(400).json({ message: "Invalid Item ID format" });
    }

    const item = await itemsCollection.findOne({
      _id: ObjectId.createFromHexString(itemId),
    });

    if (!item) {
      return res.status(404).json({ message: "Item not found" });
    }

    const {
      item_store = 0,
      item_use = 0,
      item_faulty_store = 0,
      item_faulty_use = 0,
      item_transfer = 0,
    } = items_quantity;

    const quantities = [
      item_store,
      item_use,
      item_faulty_store,
      item_faulty_use,
      item_transfer,
    ];

    const hasInvalidQty = quantities.some(
      (qty) => Number(qty) < 0 || isNaN(Number(qty))
    );

    const hasZeroQty = quantities.every((qty) => Number(qty) === 0);

    if (hasInvalidQty) {
      return res.status(400).json({ error: "Invalid quantity value" });
    }

    if (hasZeroQty) {
      return res
        .status(400)
        .json({ error: "At least one quantity must be greater than 0" });
    }

    // ✅ Convert all numeric fields to Double
    const newRecord = {
      itemName,
      model,
      category,
      date,
      status,
      itemId: ObjectId.createFromHexString(itemId),
      items_quantity: {
        item_store: new Double(parseFloat(item_store) || 0),
        item_use: new Double(parseFloat(item_use) || 0),
        item_faulty_store: new Double(parseFloat(item_faulty_store) || 0),
        item_faulty_use: new Double(parseFloat(item_faulty_use) || 0),
        item_transfer: new Double(parseFloat(item_transfer) || 0),
      },
      purpose,
      locationGood,
    };

    const result = await recordsCollection.insertOne(newRecord);
    res.status(200).send(result);
  } catch (err) {
    console.error("Error creating record:", err);
    res.status(500).json({ message: "Failed to create record" });
  }
});


  // 🔒 Delete record
  app.delete(`${prefix}/records/:id`, verifyToken, async (req, res) => {
    const result = await recordsCollection.deleteOne({
      _id: new ObjectId(req.params.id),
    });
    res.send(result);
  });

  // 🔒 Approve record (and update item quantities)

app.patch(`${prefix}/records/approve/:id`, verifyToken, async (req, res) => {
  try {
    const id = req.params.id;

    // Validate ID format
    if (!id || !ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    const _id = new ObjectId(id);

    // Fetch record
    const record = await recordsCollection.findOne({ _id });
    if (!record) return res.status(404).send({ message: "Record not found" });

    // Fetch associated item
    const item = await itemsCollection.findOne({ _id: new ObjectId(record.itemId) });
    if (!item) return res.status(404).send({ message: "Item not found" });

    // Existing quantities
    let {
      item_store = 0,
      item_use = 0,
      item_faulty_store = 0,
      item_faulty_use = 0,
      item_transfer = 0,
    } = item.items_quantity || {};

    // Total quantity
    let totalQuantity = parseFloat(item.totalQuantity || 0);

    // Record quantities
    const rq = record.items_quantity || {};
    const storeQty = parseFloat(rq.item_store || 0);
    const useQty = parseFloat(rq.item_use || 0);
    const faultyStoreQty = parseFloat(rq.item_faulty_store || 0);
    const faultyUseQty = parseFloat(rq.item_faulty_use || 0);
    const transferQty = parseFloat(rq.item_transfer || 0);

    const rawStatus = (record.status || "").trim().toLowerCase();

    // Update logic
    if (rawStatus === "pending(add)") {
      item_store += storeQty;
      totalQuantity += storeQty;
    } else if (rawStatus === "pending(remove)") {
      item_store -= useQty;
      item_use += useQty;
    } else if (rawStatus === "pending(remove_fault_store)") {
      item_store -= faultyStoreQty;
      item_faulty_store += faultyStoreQty;
    } else if (rawStatus === "pending(remove_fault_use)") {
      item_use -= faultyUseQty;
      item_faulty_use += faultyUseQty;
    } else if (rawStatus === "pending(transfer)") {
      item_store -= transferQty;
      item_transfer += transferQty;
    }

    // Update the item with all quantities as Double
    await itemsCollection.updateOne(
      { _id: item._id },
      {
        $set: {
          "items_quantity.item_store": new Double(Math.max(0, item_store)),
          "items_quantity.item_use": new Double(Math.max(0, item_use)),
          "items_quantity.item_faulty_store": new Double(Math.max(0, item_faulty_store)),
          "items_quantity.item_faulty_use": new Double(Math.max(0, item_faulty_use)),
          "items_quantity.item_transfer": new Double(Math.max(0, item_transfer)),
          totalQuantity: new Double(Math.max(0, totalQuantity)),
        },
      }
    );

    // Mark the record as approved
    const updateResult = await recordsCollection.updateOne(
      { _id },
      { $set: { status: "approved" } }
    );

    res.send({ message: "Approved", updateResult });
  } catch (error) {
    console.error("Approval error:", error);
    res.status(500).send({ message: "Failed to approve record" });
  }
});

}

// Centralized users routes (only in ims-main)
function createUserRoutes() {
  const db = getDB("main"); // ims-main database
  const usersCollection = db.collection("users");

  // 🔐 GET all users
  app.get("/users", verifyToken, async (req, res) => {
    const result = await usersCollection.find().toArray();
    res.send(result);
  });

  // 🔐 Create a user (recommended protected, or use public with caution)
  app.post("/user", verifyToken, async (req, res) => {
    const result = await usersCollection.insertOne(req.body);
    res.send(result);
  });

  // 🔐 Get user by email
  app.get("/user/:email", verifyToken, async (req, res) => {
    const result = await usersCollection.findOne({ email: req.params.email });
    if (!result) return res.status(404).send({ message: "User not found" });
    res.send(result);
  });

  // 🔐 Update user status
  app.patch("/users/status/:id", verifyToken, async (req, res) => {
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status: req.body.status } }
    );
    res.send(result);
  });

  // 🔐 Update access block
  app.patch("/users/accessBlock/:id", verifyToken, async (req, res) => {
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { accessBlock: req.body.accessBlock } }
    );
    res.send(result);
  });

  // 🔐 Delete user
  app.delete("/users/:id", verifyToken, async (req, res) => {
    const result = await usersCollection.deleteOne({
      _id: new ObjectId(req.params.id),
    });
    res.send(result);
  });
}

// 🔥 Notifications Routes (in ims-main DB)
function createNotificationRoutes() {
  const notificationsCollection = dbMap["main"].collection("notifications");

  // Get all notifications (can filter later by role if needed)

  app.get("/notifications/all", verifyToken, async (req, res) => {
    const { block, type, module } = req.query;

    if (!block) {
      return res.status(400).send({ message: "Block is required" });
    }

    const filter = { block };
    if (type) filter.type = type;
    if (module) filter.module = module;

    try {
      const notifications = await notificationsCollection
        .find(filter)
        .sort({ timestamp: -1 })
        .toArray();

      res.send(notifications);
    } catch (err) {
      console.error("Failed to fetch all notifications:", err);
      res.status(500).send({ message: "Internal Server Error" });
    }
  });

  app.get("/notifications", verifyToken, async (req, res) => {
    const { block, skip = 0, limit = 5, type, module } = req.query;

    const filter = { block };
    if (type) filter.type = type;
    if (module) filter.module = module;

    const notifications = await notificationsCollection
      .find(filter)
      .sort({ timestamp: -1 })
      .skip(parseInt(skip))
      .limit(parseInt(limit))
      .toArray();

    res.send(notifications);
  });

  // Mark notification as seen
  app.patch("/notifications/mark/:id", verifyToken, async (req, res) => {
    const result = await notificationsCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { seen: true } }
    );
    res.send(result);
  });

  app.patch("/notifications/mark-all", verifyToken, async (req, res) => {
    const { block, module } = req.query;

    if (!block || !module) {
      return res.status(400).send({ message: "Block and module are required" });
    }

    try {
      const result = await notificationsCollection.updateMany(
        { block, module, seen: false },
        { $set: { seen: true } }
      );
      res.send(result);
    } catch (err) {
      console.error("Failed to mark notifications as seen:", err);
      res.status(500).send({ message: "Internal Server Error" });
    }
  });

  // Delete notification
  app.delete("/notifications/:id", verifyToken, async (req, res) => {
    const result = await notificationsCollection.deleteOne({
      _id: new ObjectId(req.params.id),
    });
    res.send(result);
  });

  app.get("/notifications/count", verifyToken, async (req, res) => {
    const { block, module } = req.query;

    if (!block || !module) {
      return res.status(400).send({ message: "Block and module are required" });
    }

    try {
      const count = await notificationsCollection.countDocuments({
        block,
        module,
        seen: false,
      });
      res.send({ count });
    } catch (err) {
      console.error("Failed to count notifications:", err);
      res.status(500).send({ message: "Internal Server Error" });
    }
  });
}

// Start the server
connectDatabases().then(() => {
  createRoutesForBlock("head");
  createRoutesForBlock("local");
  createUserRoutes();
  createNotificationRoutes();

  app.get("/", (req, res) => res.send("✅ SMS is running ok"));
  app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
});
