package com.yuzx.app.security

/**
 * Granular destruction scope checklist for emergency Nuke execution.
 */
data class NukeScope(
    val wipeLocalData: Boolean = true,
    val wipeChatMessages: Boolean = true,
    val wipePersonalVault: Boolean = true,
    val wipeCallLogs: Boolean = true,
    val deleteFullAccount: Boolean = false,
) {
    fun toList(): List<String> = buildList {
        if (wipeLocalData) add("local_data")
        if (wipeChatMessages) add("messages")
        if (wipePersonalVault) add("vault")
        if (wipeCallLogs) add("calls")
        if (deleteFullAccount) add("account")
    }

    companion object {
        fun fromList(list: List<String>): NukeScope {
            return NukeScope(
                wipeLocalData = list.contains("local_data"),
                wipeChatMessages = list.contains("messages"),
                wipePersonalVault = list.contains("vault"),
                wipeCallLogs = list.contains("calls"),
                deleteFullAccount = list.contains("account"),
            )
        }
    }
}

enum class LockMode {
    NORMAL,
    CIPHER,
}

sealed interface UnlockResult {
    data object NormalSuccess : UnlockResult
    data object CipherSuccess : UnlockResult
    data class NukeTriggered(val scope: NukeScope) : UnlockResult
    data object Failed : UnlockResult
}
