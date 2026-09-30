package dev.busung.s25uroot

import android.content.Context
import android.system.Os
import java.io.File
import java.io.FileOutputStream

data class VerifiedPayloads(
    val profile: TargetProfile,
    val exploit: File,
    val kernelSu: File,
    val helper: File,
    val launcher: File,
    val mmFactory: File?,
)

/**
 * Payload source is always the APK's own assets. The manifest (`targets-v3.json`)
 * and every artifact are bundled, so the app never touches the network to root:
 * a device with no connectivity behaves identically to one online, and a payload
 * can never drift from the version that was reviewed and shipped.
 */
class PayloadRepository(private val context: Context) {
    fun loadTargets(): List<TargetProfile> {
        val manifestBytes = context.assets.open("targets-v3.json").use { input ->
            input.readBytes()
        }
        return SupportManifest.parse(manifestBytes).targets
    }

    fun resolveTarget(snapshot: DeviceSnapshot): TargetProfile = loadTargets()
        .filter { it.matches(snapshot) }
        .maxByOrNull { it.specificity }
        ?: throw UnsupportedFirmwareException(
            message = context.getString(R.string.error_firmware_unsupported, snapshot.buildId),
            firmware = snapshot.buildId,
            helpTitle = context.getString(R.string.error_firmware_one_ui_9_title)
                .takeIf { snapshot.isOneUi9 },
            helpMessage = context.getString(R.string.error_firmware_one_ui_9_help)
                .takeIf { snapshot.isOneUi9 },
        )

    fun resolveTarget(profileId: String): TargetProfile = loadTargets()
        .firstOrNull { it.profileId == profileId }
        ?: error(context.getString(R.string.repo_profile_missing, profileId))

    fun download(profile: TargetProfile, onProgress: (String) -> Unit): VerifiedPayloads {
        val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }
        val exploit = bundledAssetFor(profile.exploit, directory, onProgress,
            context.getString(R.string.artifact_exploit_bundled))
            ?: error("bundled exploit missing: ${profile.exploit.url}")
        val kernelSu = bundledAssetFor(profile.kernelSu, directory, onProgress,
            context.getString(R.string.artifact_kernelsu_bundled))
            ?: error("bundled KernelSU missing: ${profile.kernelSu.url}")
        val helper = bundledAssetFor(profile.helper, directory, onProgress,
            context.getString(R.string.artifact_helper_bundled))
            ?: error("bundled helper missing: ${profile.helper.url}")
        val launcherLabel = context.getString(R.string.artifact_launcher_bundled)
        val launcher = profile.launcher?.let { artifact ->
            bundledAssetFor(artifact, directory, onProgress, launcherLabel)
                ?: error("bundled launcher missing: ${artifact.url}")
        } ?: error("bundled launcher missing: ${profile.profileId}")
        val mmFactory = profile.mmFactory?.let { artifact ->
            bundledAssetFor(
                artifact,
                directory,
                onProgress,
                context.getString(R.string.artifact_mm_factory_bundled),
            ) ?: error("bundled mm factory missing: ${artifact.url}")
        }
        Os.chmod(exploit.absolutePath, 0b100100100)
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        Os.chmod(helper.absolutePath, 0b111101101)
        Os.chmod(launcher.absolutePath, 0b111101101)
        mmFactory?.let { Os.chmod(it.absolutePath, 0b111101101) }
        return VerifiedPayloads(profile, exploit, kernelSu, helper, launcher, mmFactory)
    }

    private fun bundledAssetFor(
        artifact: RemoteArtifact,
        directory: File,
        onProgress: (String) -> Unit,
        label: String,
    ): File? {
        if (!artifact.url.startsWith(ASSET_PREFIX)) return null
        val name = artifact.url.removePrefix(ASSET_PREFIX)
        require(name.isNotBlank() && File(name).name == name) { "Invalid bundled asset name" }
        return bundledAsset(name, artifact.size, directory, onProgress, label)
    }

    /** 从 APK assets 解出内嵌文件；失败返回 null。 */
    private fun bundledAsset(name: String, expectedSize: Long, directory: File, onProgress: (String) -> Unit, label: String): File? {
        return try {
            val destination = File(directory, name)
            // v0.2.36: 第二次运行修复——上次解出的文件被 chmod 0444（只读），
            // 再次 FileOutputStream 写入会 Permission denied。
            // 先删除旧文件（幂等），确保每次都能全新写入；删除失败则用 .tmp 新名兜底。
            if (destination.exists()) {
                if (!destination.delete()) {
                    // 只读文件删不掉（极端情况）→ 换新名写入，避免 Permission denied
                    val alt = File(directory, "${name}.${System.currentTimeMillis()}.tmp")
                    FileOutputStream(alt).use { output ->
                        context.assets.open(name).use { input -> input.copyTo(output) }
                        output.fd.sync()
                    }
                    require(alt.length() == expectedSize) { "Bundled asset size mismatch: $name" }
                    onProgress(label)
                    return alt
                }
            }
            FileOutputStream(destination).use { output ->
                context.assets.open(name).use { input ->
                    input.copyTo(output)
                }
                output.fd.sync()
            }
            require(destination.length() == expectedSize) { "Bundled asset size mismatch: $name" }
            onProgress(label)
            destination
        } catch (e: Throwable) {
            null
        }
    }

    companion object {
        private const val ASSET_PREFIX = "asset://"
    }
}

class UnsupportedFirmwareException(
    message: String,
    val firmware: String,
    val helpTitle: String?,
    val helpMessage: String?,
) : IllegalStateException(message)
