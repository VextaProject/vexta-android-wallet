package org.vextaproject.wallet

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        if (
            intent?.action != Intent.ACTION_BOOT_COMPLETED &&
            intent?.action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            return
        }

        val walletExists =
            context.getSharedPreferences(
                "vexta_wallet",
                Context.MODE_PRIVATE
            ).contains("seed_ciphertext")

        if (!walletExists) {
            return
        }

        val monitoringIntent =
            Intent(context, WalletMonitoringService::class.java)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(monitoringIntent)
        } else {
            context.startService(monitoringIntent)
        }
    }
}
