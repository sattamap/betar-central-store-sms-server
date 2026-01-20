const express = require("express");
require("dotenv").config();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

// https://betar-central-store-sms-server.onrender.com
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

// const verifyToken = async (req, res, next) => {
//   const token = req.cookies.token;
//   if (!token) return res.status(401).send({ message: "Unauthorized" });

//   jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, async (err, decoded) => {
//     if (err) {
//       if (err.name === "TokenExpiredError") {
//         return res.status(401).send({ message: "TokenExpired" });
//       }
//       return res.status(403).send({ message: "Forbidden" });
//     }

//     try {
//       // ✅ GET DB SAFELY HERE
//       const db = getDB("main");
//       const usersCollection = db.collection("users");

//       const user = await usersCollection.findOne({ email: decoded.email });

//       if (!user) {
//         return res.status(401).send({ message: "User not found" });
//       }

//       req.user = {
//         uid: user.uid || user._id.toString(),
//         name: user.name,
//         email: user.email,
//         status: user.status,
//       };

//       next();
//     } catch (error) {
//       console.error("verifyToken error:", error);
//       res.status(500).send({ message: "Auth failed" });
//     }
//   });
// };

const verifyToken = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).send({ message: "Unauthorized" });

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, async (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).send({ message: "TokenExpired" });
      }
      return res.status(403).send({ message: "Forbidden" });
    }

    try {
      const db = getDB("main");
      const usersCollection = db.collection("users");

      const user = await usersCollection.findOne({ email: decoded.email });
      if (!user) return res.status(401).send({ message: "User not found" });

      req.user = user;
      next();
    } catch (err) {
      res.status(500).send({ message: "Auth failed" });
    }
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
      newItem.items_quantity.item_store = new Double(
        newItem.items_quantity.item_store || 0
      );
      newItem.items_quantity.item_use = new Double(
        newItem.items_quantity.item_use || 0
      );
      newItem.items_quantity.item_faulty_store = new Double(
        newItem.items_quantity.item_faulty_store || 0
      );
      newItem.items_quantity.item_faulty_use = new Double(
        newItem.items_quantity.item_faulty_use || 0
      );
      newItem.items_quantity.item_transfer = new Double(
        newItem.items_quantity.item_transfer || 0
      );
    }

    newItem.totalQuantity = new Double(newItem.totalQuantity || 0);

    const result = await itemsCollection.insertOne(newItem);

    // ✅ Notification (dynamic role from DB)
    const notificationsCollection = dbMap["main"].collection("notifications");

    const roleLabel =
      req.user?.status === "admin"
        ? "Admin"
        : req.user?.status === "coordinator"
        ? "Coordinator"
        : "User";

    await notificationsCollection.insertOne({
      type: "item_added",
      module: "items",
      message: `${roleLabel} ${req.user.email} added "${newItem.itemName}" (${
        newItem.model
      }) in ${block.toUpperCase()} block.`,
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

      // ✅ Notify Admin after successful update (dynamic role)
      const updatedItem = req.body;
      const notificationsCollection = dbMap["main"].collection("notifications");

      const roleLabel =
        req.user?.status === "admin"
          ? "Admin"
          : req.user?.status === "coordinator"
          ? "Coordinator"
          : "User";

      await notificationsCollection.insertOne({
        type: "item_updated",
        module: "items",
        message: `${roleLabel} ${req.user.email} updated "${
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

      const roleLabel =
        req.user?.status === "admin"
          ? "Admin"
          : req.user?.status === "coordinator"
          ? "Coordinator"
          : "User";

      await notificationsCollection.insertOne({
        type: "service_added",
        module: "services",
        message: `${roleLabel} ${req.user.email} added new service "${
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
        // ✅ Auto-notify Admin after service update (dynamic role)
        const notificationsCollection =
          dbMap["main"].collection("notifications");

        const roleLabel =
          req.user?.status === "admin"
            ? "Admin"
            : req.user?.status === "coordinator"
            ? "Coordinator"
            : "User";

        await notificationsCollection.insertOne({
          type: "service_updated",
          module: "services",
          message: `${roleLabel} ${req.user.email} updated "${
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

  app.get(`${prefix}/records`, verifyToken, async (req, res) => {
    try {
      const q = {}; // you can add query filters later via req.query
      const docs = await recordsCollection.find(q).toArray();
      res.json(docs);
    } catch (err) {
      console.error("GET records error", err);
      res.status(500).json({ message: "Failed to fetch records" });
    }
  });

  // POST /records  -> Monitor submits request
  app.post(`${prefix}/records`, verifyToken, async (req, res) => {
    try {
      const {
        itemName,
        model,
        category,
        date,
        itemId,
        items_quantity = {},
        purpose,
        locationGood,
        requestedBy: requestedByFromClient,
        actionStatus,
        workflowStatus,
      } = req.body;

      if (!itemId || !ObjectId.isValid(itemId)) {
        return res.status(400).json({ message: "Invalid itemId" });
      }

      const item = await itemsCollection.findOne({ _id: new ObjectId(itemId) });
      if (!item) return res.status(404).json({ message: "Item not found" });

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
      if (quantities.some((q) => Number(q) < 0 || isNaN(Number(q)))) {
        return res.status(400).json({ message: "Invalid quantity values" });
      }
      if (quantities.every((q) => Number(q) === 0)) {
        return res
          .status(400)
          .json({ message: "At least one quantity must be > 0" });
      }

      const requester = requestedByFromClient || {
        uid: req.user?.uid || null,
        name:
          req.user?.displayName || req.user?.name || req.user?.email || null,
        email: req.user?.email || null,
        role: req.user?.role || "monitor",
      };

      const newRecord = {
        itemName: itemName || item.itemName,
        model: model || item.model,
        category: category || item.category,
        date: date || new Date().toISOString().split("T")[0],
        actionStatus, // What will happen to inventory
        workflowStatus: workflowStatus || "submitted_by_monitor", // Where in workflow
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
        requestedBy: requester,
        forwardedBy: null,
        finalApprovedBy: null,
        acceptedBy: null,
        workflowHistory: [
          {
            action: "submitted",
            actor: {
              uid: requester.uid,
              name: requester.name,
              email: requester.email,
              role: requester.role,
            },
            actionStatus,
            workflowStatus: workflowStatus || "submitted_by_monitor",
            date: new Date(),
          },
        ],
        createdAt: new Date(),
      };

      const result = await recordsCollection.insertOne(newRecord);
      res.status(201).json({ message: "Created", id: result.insertedId });
    } catch (err) {
      console.error("POST /records error", err);
      res.status(500).json({ message: "Failed to create record" });
    }
  });

  // PATCH /records/forward/:id  -> Coordinator forwards to Admin
  app.patch(`${prefix}/records/forward/:id`, verifyToken, async (req, res) => {
    try {
      const id = req.params.id;
      if (!ObjectId.isValid(id))
        return res.status(400).json({ message: "Invalid id" });

      const _id = new ObjectId(id);
      const record = await recordsCollection.findOne({ _id });
      if (!record) return res.status(404).json({ message: "Record not found" });

      // Only coordinator (or monitor who submitted) should forward — optionally check req.user.role
      const forwarder = {
        uid: req.user?.uid || null,
        name:
          req.user?.displayName || req.user?.name || req.user?.email || null,
        email: req.user?.email || null,
        role: req.user?.role || "coordinator",
      };

      const newWorkflowItem = {
        action: "forwarded_to_admin",
        actor: forwarder,
        actionStatus: record.actionStatus,
        workflowStatus: "forwarded_to_admin",
        date: new Date(),
      };

      await recordsCollection.updateOne(
        { _id },
        {
          $set: {
            workflowStatus: "forwarded_to_admin",
            forwardedBy: forwarder,
            status: record.actionStatus, // keep status consistent
          },
          $push: { workflowHistory: newWorkflowItem },
        }
      );

      res.json({ message: "Forwarded to admin" });
    } catch (err) {
      console.error("PATCH forward error", err);
      res.status(500).json({ message: "Failed to forward" });
    }
  });

  // PATCH /records/admin-approve/:id  -> Admin approves and updates item quantities
  app.patch(
    `${prefix}/records/admin-approve/:id`,
    verifyToken,
    async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id))
          return res.status(400).json({ message: "Invalid id" });
        const _id = new ObjectId(id);

        const record = await recordsCollection.findOne({ _id });
        if (!record)
          return res.status(404).json({ message: "Record not found" });

        // Only admin should approve — optional role check:
        // if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });

        // Fetch associated item
        const item = await itemsCollection.findOne({
          _id: new ObjectId(record.itemId),
        });
        if (!item) return res.status(404).json({ message: "Item not found" });

        // Current item quantities (numbers)
        const iq = item.items_quantity || {};
        let item_store = parseFloat(iq.item_store || 0);
        let item_use = parseFloat(iq.item_use || 0);
        let item_faulty_store = parseFloat(iq.item_faulty_store || 0);
        let item_faulty_use = parseFloat(iq.item_faulty_use || 0);
        let item_transfer = parseFloat(iq.item_transfer || 0);
        let totalQuantity = parseFloat(item.totalQuantity || 0);

        // Record quantities (what monitor requested)
        const rq = record.items_quantity || {};
        const storeQty = parseFloat(rq.item_store || 0);
        const useQty = parseFloat(rq.item_use || 0);
        const faultyStoreQty = parseFloat(rq.item_faulty_store || 0);
        const faultyUseQty = parseFloat(rq.item_faulty_use || 0);
        const transferQty = parseFloat(rq.item_transfer || 0);

        // Apply action depending on actionStatus
        const rawAction = (record.actionStatus || record.status || "")
          .trim()
          .toLowerCase(); // e.g. pending(add)
        if (rawAction === "pending(add)" || rawAction === "pending (add)") {
          item_store += storeQty;
          totalQuantity += storeQty;
        } else if (
          rawAction === "pending(remove)" ||
          rawAction === "pending (remove)"
        ) {
          item_store = Math.max(0, item_store - useQty);
          item_use += useQty;
        } else if (
          rawAction === "pending(remove_fault_store)" ||
          rawAction === "pending (remove_fault_store)"
        ) {
          item_store = Math.max(0, item_store - faultyStoreQty);
          item_faulty_store += faultyStoreQty;
        } else if (
          rawAction === "pending(remove_fault_use)" ||
          rawAction === "pending (remove_fault_use)"
        ) {
          item_use = Math.max(0, item_use - faultyUseQty);
          item_faulty_use += faultyUseQty;
        } else if (
          rawAction === "pending(transfer)" ||
          rawAction === "pending (transfer)"
        ) {
          item_store = Math.max(0, item_store - transferQty);
          item_transfer += transferQty;
        } else {
          // unknown action -> do nothing; but still allow admin to mark approved if desired
        }

        // Commit item updates
        await itemsCollection.updateOne(
          { _id: item._id },
          {
            $set: {
              "items_quantity.item_store": new Double(Math.max(0, item_store)),
              "items_quantity.item_use": new Double(Math.max(0, item_use)),
              "items_quantity.item_faulty_store": new Double(
                Math.max(0, item_faulty_store)
              ),
              "items_quantity.item_faulty_use": new Double(
                Math.max(0, item_faulty_use)
              ),
              "items_quantity.item_transfer": new Double(
                Math.max(0, item_transfer)
              ),
              totalQuantity: new Double(Math.max(0, totalQuantity)),
            },
          }
        );

        // Save admin approval metadata
        const approver = {
          uid: req.user?.uid || null,
          name:
            req.user?.displayName || req.user?.name || req.user?.email || null,
          email: req.user?.email || null,
          role: req.user?.role || "admin",
        };

        const workflowItem = {
          action: "admin_approved",
          actor: approver,
          actionStatus: record.actionStatus,
          workflowStatus: "admin_approved",
          date: new Date(),
        };

        await recordsCollection.updateOne(
          { _id },
          {
            $set: {
              workflowStatus: "admin_approved",
              finalApprovedBy: approver,
              status: record.actionStatus, // keep backward compatibility
            },
            $push: { workflowHistory: workflowItem },
          }
        );

        return res.json({ message: "Approved and inventory updated" });
      } catch (err) {
        console.error("admin approve error", err);
        res.status(500).json({ message: "Failed to approve" });
      }
    }
  );

  // PATCH /records/send-to-coordinator/:id
  app.patch(
    `${prefix}/records/send-to-coordinator/:id`,
    verifyToken,
    async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid record id" });
        }

        const record = await recordsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!record) {
          return res.status(404).json({ message: "Record not found" });
        }

        // Optional: admin role check
        // if (req.user.role !== "admin") {
        //   return res.status(403).json({ message: "Forbidden" });
        // }

        const admin = {
          uid: req.user?.uid || null,
          name: req.user?.displayName || req.user?.name || null,
          email: req.user?.email || null,
          role: "admin",
        };

        await recordsCollection.updateOne(
          { _id: record._id },
          {
            $set: {
              workflowStatus: "sent_back_to_coordinator",
            },
            $push: {
              workflowHistory: {
                action: "sent_back_to_coordinator",
                actor: admin,
                workflowStatus: "sent_back_to_coordinator",
                date: new Date(),
              },
            },
          }
        );

        res.json({ message: "Sent back to coordinator" });
      } catch (err) {
        console.error("send to coordinator error", err);
        res.status(500).json({ message: "Failed to send" });
      }
    }
  );

  // PATCH /records/send-to-monitor/:id
  app.patch(
    `${prefix}/records/send-to-monitor/:id`,
    verifyToken,
    async (req, res) => {
      try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid record id" });
        }

        const record = await recordsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!record) {
          return res.status(404).json({ message: "Record not found" });
        }

        // Optional role check (recommended)
        // if (req.user.role !== "coordinator") {
        //   return res.status(403).json({ message: "Forbidden" });
        // }

        const coordinator = {
          uid: req.user?.uid || null,
          name: req.user?.displayName || req.user?.name || null,
          email: req.user?.email || null,
          role: "coordinator",
        };

        await recordsCollection.updateOne(
          { _id: record._id },
          {
            $set: {
              workflowStatus: "sent_back_to_monitor",
            },
            $push: {
              workflowHistory: {
                action: "sent_back_to_monitor",
                actor: coordinator,
                workflowStatus: "sent_back_to_monitor",
                date: new Date(),
              },
            },
          }
        );

        res.json({ message: "Sent to monitor successfully" });
      } catch (err) {
        console.error("send to monitor error", err);
        res.status(500).json({ message: "Failed to send to monitor" });
      }
    }
  );

  // PATCH /records/accept-by-monitor/:id
  app.patch(
    `${prefix}/records/accept-by-monitor/:id`,
    verifyToken,
    async (req, res) => {
      try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid record id" });
        }

        const record = await recordsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!record) {
          return res.status(404).json({ message: "Record not found" });
        }

        // Optional role check
        // if (req.user.role !== "monitor") {
        //   return res.status(403).json({ message: "Forbidden" });
        // }

        const monitor = {
          uid: req.user?.uid || null,
          name: req.user?.displayName || req.user?.name || null,
          email: req.user?.email || null,
          role: "monitor",
        };

        await recordsCollection.updateOne(
          { _id: record._id },
          {
            $set: {
              workflowStatus: "accepted_by_monitor",
              acceptedBy: monitor,
            },
            $push: {
              workflowHistory: {
                action: "accepted_by_monitor",
                actor: monitor,
                workflowStatus: "accepted_by_monitor",
                date: new Date(),
              },
            },
          }
        );

        res.json({ message: "Record accepted by monitor" });
      } catch (err) {
        console.error("accept by monitor error", err);
        res.status(500).json({ message: "Failed to accept record" });
      }
    }
  );

  // 🔒 Delete record
  app.delete(`${prefix}/records/:id`, verifyToken, async (req, res) => {
    const result = await recordsCollection.deleteOne({
      _id: new ObjectId(req.params.id),
    });
    res.send(result);
  });

  // PATCH /records/admin-reject/:id  -> Admin rejects (returns to coordinator)
  app.patch(
    `${prefix}/records/admin-reject/:id`,
    verifyToken,
    async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id))
          return res.status(400).json({ message: "Invalid id" });
        const _id = new ObjectId(id);
        const record = await recordsCollection.findOne({ _id });
        if (!record)
          return res.status(404).json({ message: "Record not found" });

        const admin = {
          uid: req.user?.uid,
          name: req.user?.displayName || req.user?.name || req.user?.email,
          role: req.user?.role || "admin",
        };
        const workflowItem = {
          action: "admin_rejected",
          actor: admin,
          actionStatus: record.actionStatus,
          workflowStatus: "admin_rejected",
          date: new Date(),
        };

        await recordsCollection.updateOne(
          { _id },
          {
            $set: {
              workflowStatus: "admin_rejected",
              status: record.actionStatus,
            },
            $push: { workflowHistory: workflowItem },
          }
        );

        res.json({ message: "Rejected and returned to coordinator" });
      } catch (err) {
        console.error("admin reject error", err);
        res.status(500).json({ message: "Failed to reject" });
      }
    }
  );
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
  // app.post("/user", verifyToken, async (req, res) => {
  //   const result = await usersCollection.insertOne(req.body);
  //   res.send(result);
  // });

  app.post("/user", async (req, res) => {
    const user = req.body;

    const existingUser = await usersCollection.findOne({
      email: user.email,
    });

    if (existingUser) {
      return res.send({ message: "User already exists" });
    }

    const result = await usersCollection.insertOne(user);
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
