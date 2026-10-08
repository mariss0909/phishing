import { initializeApp } from "https://www.gstatic.com/firebasejs/13.0.0/firebase-app.js";
import { getAuth, signInAnonymously } from "https://www.gstatic.com/firebasejs/13.0.0/firebase-auth.js";
import {
	addDoc,
	collection,
	deleteDoc,
	doc,
	getDocs,
	getFirestore,
	setDoc,
	writeBatch,
} from "https://www.gstatic.com/firebasejs/13.0.0/firebase-firestore.js";

const firebaseConfig = {
	apiKey: "AIzaSyD3wrtpj3KuqRAXSepb1sGdFAYP-jLzqwg",
	authDomain: "phishing-fdb91.firebaseapp.com",
	projectId: "phishing-fdb91",
	storageBucket: "phishing-fdb91.firebasestorage.app",
	messagingSenderId: "426222016200",
	appId: "1:426222016200:web:c1246afcc82749d70b77fd",
	measurementId: "G-9GLX14J11S",
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const database = getFirestore(app);

function userCollection(userId, name) {
	return collection(database, "users", userId, name);
}

function stableDocumentId(collectionName, value) {
	return `${collectionName}-${encodeURIComponent(String(value))}`;
}

function deriveMainDomain(source) {
	try {
		const labels = new URL(source).hostname.toLowerCase().replace(/^www\./, "").split(".");
		if (labels.length < 2) return labels[0] || "";
		const compoundSuffixes = new Set(["com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph", "mil.ph"]);
		return labels.length > 2 && compoundSuffixes.has(labels.slice(-2).join(".")) ? labels.slice(-3).join(".") : labels.slice(-2).join(".");
	} catch {
		return "";
	}
}

function normalizeRecord(collectionName, record) {
	return collectionName === "official_directory" ? { ...record, mainDomain: record.mainDomain || deriveMainDomain(record.source) } : record;
}

function normalizeDocument(snapshot) {
	const data = snapshot.data();
	if (data.createdAt?.toDate) data.createdAt = data.createdAt.toDate().toISOString();
	return { ...data, id: snapshot.id };
}

async function readLegacyData(path, property, fallback = []) {
	try {
		const response = await fetch(path, { cache: "no-store" });
		if (!response.ok) return fallback;
		const data = await response.json();
		return Array.isArray(data[property]) ? data[property] : fallback;
	} catch {
		return fallback;
	}
}

async function migrateIfEmpty(userId, collectionName, path, property, fallback, getKey) {
	const target = userCollection(userId, collectionName);
	if (!(await getDocs(target)).empty) return;
	const records = await readLegacyData(path, property, fallback);
	if (!records.length) return;
	const batch = writeBatch(database);
	for (const record of records) {
		const key = getKey(record);
		const normalized = normalizeRecord(collectionName, record);
		batch.set(doc(target, stableDocumentId(collectionName, key)), { ...normalized, id: stableDocumentId(collectionName, key) });
	}
	await batch.commit();
}

window.firebaseStoreReady = (async () => {
	const { user } = await signInAnonymously(auth);
	await Promise.all([
		migrateIfEmpty(user.uid, "official_directory", "/api/directory", "entries", window.initialOfficialDirectory || [], entry => entry.organization),
		migrateIfEmpty(user.uid, "contacts", "/api/contacts", "contacts", [], contact => contact.id),
		migrateIfEmpty(user.uid, "reports", "/api/reports", "reports", [], report => report.id),
	]);
	return user.uid;
})();
window.firebaseStoreReady.catch(error => console.error("Firestore setup failed:", error));

async function getRecords(userId, collectionName) {
	const snapshot = await getDocs(userCollection(userId, collectionName));
	return snapshot.docs.map(normalizeDocument);
}

async function firebaseDataRequest(path, options = {}) {
	const userId = await window.firebaseStoreReady;
	const method = (options.method || "GET").toUpperCase();
	const payload = options.body ? JSON.parse(options.body) : {};

	if (path === "/api/directory" && method === "GET") {
		return { entries: (await getRecords(userId, "official_directory")).map(entry => normalizeRecord("official_directory", entry)) };
	}
	if (path === "/api/directory" && method === "PUT") {
		const target = userCollection(userId, "official_directory");
		const current = await getDocs(target);
		const entries = Array.isArray(payload.entries) ? payload.entries : [];
		const nextIds = new Set(entries.map(entry => stableDocumentId("official_directory", entry.organization)));
		const batch = writeBatch(database);
		for (const snapshot of current.docs) {
			if (!nextIds.has(snapshot.id)) batch.delete(snapshot.ref);
		}
		for (const entry of entries) {
			const id = stableDocumentId("official_directory", entry.organization);
			batch.set(doc(target, id), { ...normalizeRecord("official_directory", entry), id });
		}
		await batch.commit();
		return { entries };
	}
	if (path === "/api/contacts" && method === "GET") {
		return { contacts: await getRecords(userId, "contacts") };
	}
	if (path === "/api/contacts" && method === "POST") {
		const target = userCollection(userId, "contacts");
		const normalizedValue = payload.type === "email" ? payload.value.trim().toLowerCase() : payload.value.replace(/\D/g, "");
		const current = await getDocs(target);
		if (current.docs.some(snapshot => snapshot.data().normalized_value === normalizedValue && snapshot.data().type === payload.type)) {
			throw new Error("That email or phone is already saved.");
		}
		const contact = { ...payload, value: payload.value.trim(), normalized_value: normalizedValue, created_at: new Date().toISOString() };
		const created = await addDoc(target, contact);
		return { contact: { id: created.id, ...contact } };
	}
	const contactMatch = path.match(/^\/api\/contacts\/([^/]+)$/);
	if (contactMatch && method === "PUT") {
		const id = decodeURIComponent(contactMatch[1]);
		const target = userCollection(userId, "contacts");
		const normalizedValue = payload.type === "email" ? payload.value.trim().toLowerCase() : payload.value.replace(/\D/g, "");
		const current = await getDocs(target);
		if (current.docs.some(snapshot => snapshot.id !== id && snapshot.data().normalized_value === normalizedValue && snapshot.data().type === payload.type)) {
			throw new Error("That email or phone is already saved.");
		}
		const contact = { ...payload, value: payload.value.trim(), normalized_value: normalizedValue };
		await setDoc(doc(target, id), contact, { merge: true });
		return { contact: { id, ...contact } };
	}
	if (contactMatch && method === "DELETE") {
		await deleteDoc(doc(userCollection(userId, "contacts"), decodeURIComponent(contactMatch[1])));
		return { deleted: true };
	}
	if (path === "/api/reports" && method === "GET") {
		const reports = await getRecords(userId, "reports");
		reports.sort((left, right) => Date.parse(right.createdAt || "") - Date.parse(left.createdAt || ""));
		return { reports: reports.slice(0, 100) };
	}
	if (path === "/api/reports" && method === "POST") {
		const report = { ...payload, createdAt: payload.createdAt || new Date().toISOString() };
		const created = await addDoc(userCollection(userId, "reports"), report);
		return { report: { id: created.id, ...report } };
	}
	const reportMatch = path.match(/^\/api\/reports\/([^/]+)$/);
	if (reportMatch && method === "DELETE") {
		await deleteDoc(doc(userCollection(userId, "reports"), decodeURIComponent(reportMatch[1])));
		return { deleted: true };
	}
	throw new Error(`Unsupported Firestore operation: ${method} ${path}`);
}

window.firebaseDataRequest = firebaseDataRequest;