package com.yuzx.app.security

import androidx.compose.runtime.compositionLocalOf

val LocalCipherMode = compositionLocalOf { false }
val LocalDecoyRoomIds = compositionLocalOf { emptySet<String>() }

/**
 * VeraCrypt-Grade Plausible Deniability Decoy Transformer.
 *
 * When the Decoy/Cipher PIN is entered under duress or inspection:
 * Instead of displaying obvious scrambled strings like "[AES-256-GCM::...]"
 * which alert an adversary that a stealth lock is active, this engine
 * deterministically renders 100% natural, everyday innocent conversations,
 * contacts, and documents.
 *
 * Mathematically deterministic:
 * The exact same contact/room or message text always produces the exact same
 * believable persona or innocent reply across all sessions and timeline scrolling.
 */
object CipherMaskTransformer {

    private val INNOCENT_CONTACT_NAMES = listOf(
        "Rahul Sharma", "Pooja Verma", "Aman Gupta", "Sneha Patel",
        "Vikram Singh", "Rohit Verma", "Priya Nair", "Rohan Mehta",
        "Neha Sharma", "Aditya Roy", "Ananya Sen", "Karan Malhotra",
        "Deepak Joshi", "Meera Iyer", "Kavita Rao", "Arjun Nair",
        "Suresh Kumar", "Devendra Patel", "Ankit Tiwari", "Ritu Chauhan",
        "Simran Kaur", "Harsh Vardhan", "Nikhil Jain", "Shreya Das",
        "Pankaj Mishra", "Divya Menon", "Manish Saxena", "Tarun Kapoor",
        "Swiggy Delivery", "Zomato Support", "Airtel Customer Care", "Amazon Updates"
    )

    private val INNOCENT_GROUP_NAMES = listOf(
        "College Batch 2024", "Project Updates", "Flatmates 2024",
        "Weekend Sports", "Office Team Sync", "Study Group - CS",
        "Family Circle", "Trip Planning Group", "Gym Buddies"
    )

    private val INNOCENT_FOLDER_NAMES = listOf(
        "Course Notes", "Office Invoices", "Project Receipts",
        "Study Materials", "Personal Documents", "Reading List",
        "Travel Tickets", "Assignment Submissions"
    )

    private val INNOCENT_SHORT_MESSAGES = listOf(
        "Haan", "Theek hai bhai 👍", "Ok", "Done!", "Thanks",
        "Sure, will do", "Kal batata hoon", "Call karo", "Yes", "Cool", "All set 👍"
    )

    private val INNOCENT_MEDIUM_MESSAGES = listOf(
        "Haan bhai kal 5 baje milte hain",
        "Check kar liya maine, sab sahi hai 👍",
        "Drive link share kar do please",
        "Main thodi der me call karta hoon",
        "Kal kitne baje nikalna hai?",
        "Okay, I will review and let you know.",
        "Payment transfer kar diya hai, check kar lo.",
        "Bhai notes bhej de exam ke liye",
        "Sab theek hai na? Kal chal rahe hain?",
        "Reached home, will talk tomorrow.",
        "Photos bhej do please jab free ho",
        "No problem, kal connect karte hain."
    )

    private val INNOCENT_LONG_MESSAGES = listOf(
        "Maine presentation check kar li hai, baaki sab finalized hai bas last slide update karke bhej dena.",
        "Meeting kal subah 11 baje schedule hui hai, sab log time par join kar lena taaki delay na ho.",
        "Document verify ho gaya hai, maine group me bhi dal diya hai ek baar cross-check kar lo.",
        "Thanks for sharing! I've gone through all the details and everything looks good to proceed from our side.",
        "Assignment submit kar diya hai portal par. Reference links group ke description me added hain, check kar lena."
    )

    fun maskText(original: String): String {
        if (original.isBlank()) return ""
        val hash = (original.hashCode() and 0x7FFFFFFF)
        return when {
            original.length <= 12 -> {
                INNOCENT_SHORT_MESSAGES[hash % INNOCENT_SHORT_MESSAGES.size]
            }
            original.length <= 60 -> {
                INNOCENT_MEDIUM_MESSAGES[hash % INNOCENT_MEDIUM_MESSAGES.size]
            }
            else -> {
                INNOCENT_LONG_MESSAGES[hash % INNOCENT_LONG_MESSAGES.size]
            }
        }
    }

    fun maskName(original: String): String {
        if (original.isBlank()) return "Chat"
        val hash = (original.hashCode() and 0x7FFFFFFF)

        val lower = original.lowercase()
        val isGroup = lower.contains("group") || lower.contains("team") ||
            lower.contains("project") || lower.contains("batch") ||
            lower.contains("channel") || lower.contains("chat")

        val isFolder = lower.contains("folder") || lower.contains("doc") ||
            lower.contains("receipt") || lower.contains("file") ||
            lower.contains("vault") || lower.contains("study")

        return when {
            isFolder -> INNOCENT_FOLDER_NAMES[hash % INNOCENT_FOLDER_NAMES.size]
            isGroup -> INNOCENT_GROUP_NAMES[hash % INNOCENT_GROUP_NAMES.size]
            else -> INNOCENT_CONTACT_NAMES[hash % INNOCENT_CONTACT_NAMES.size]
        }
    }

    fun maskMedia(id: String): String {
        val hash = (id.hashCode() and 0x7FFFFFFF)
        return when (hash % 3) {
            0 -> "IMG_2024_${(hash % 899) + 100}.jpg"
            1 -> "Notes_Unit_${(hash % 9) + 1}.pdf"
            else -> "Invoice_Receipt_${(hash % 89) + 10}.pdf"
        }
    }
}
