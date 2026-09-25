import { UIAbility } from '@kit.AbilityKit';
import { huks } from '@kit.UniversalKeystoreKit';
import { util } from '@kit.ArkTS';
import { BusinessError } from '@kit.BasicServicesKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { http } from '@kit.NetworkKit';

interface Step {
  name: string;
  ok: boolean;
  code: number;
  detail: string;
}

interface Report {
  finished: boolean;
  run: string;
  steps: Step[];
}

class ProbeError extends Error {
  code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

interface TsmsHeader {
  cty: string;
  alg: string;
  kid: string;
  x5c: string[];
}

interface TsmsPayload {
  packageName: string;
  appId: string;
  pbk: string;
  alg: number;
  kekAlg: number;
  akskVersion: number;
  dkAlgLen: number;
}

interface TsmsEnvelope {
  request: string;
}

interface TsmsCredentialResponse {
  accessKey: string;
  dataKey: string;
  kek: string;
  secretKey: string;
}

interface TsmsKek {
  key: string;
}

interface HarmonyInfo {
  harmonyApiLevel: number;
  harmonyReleaseType: string;
  hmosApiLevel: number;
  hmosReleaseType: string;
  arkSupport: number;
  arkMinVersion: number;
  arkMaxVersion: number;
  harmonyDeviceType: string;
  glVersion: string;
  compatibleDeviceTypes: string[];
  deviceFeatures: string;
  ohMinorApiVersion: number;
  ohPatchApiVersion: number;
}

interface ContainerInfo {
  firmwareVersion: string;
  emuiApiLevel: number;
}

interface HarmonyDeviceParams {
  country: string[];
  deviceTypes: string[];
  apps: string;
}

interface HarmonyFetchBody {
  deviceIdType: string;
  harmonyDeviceType: string;
  serviceType: number;
  phoneType: string;
  abis: string;
  recommendSwitch: number;
  model: string;
  marketName: string;
  clientPackage: string;
  timeZone: string;
  accountZone: string;
  issueZone: string;
  density: number;
  locale: string;
  singleHarmonyClient: string;
  net: number;
  ts: number;
  code: string;
  harmonyInfo: HarmonyInfo;
  containerInfo: ContainerInfo;
  isSubUser: number;
  manufacturer: string;
  brand: string;
  runMode: number;
  deviceId: string;
  clientCapability: string;
  pcEmulator: number;
  clientVersion: string;
  clientVersionCode: string;
  deviceHomeCountry: string;
  apsid: string;
  oaid: string;
  screenInfo: string;
  osAccountId: number;
  businessMode: number;
  deviceRiskScore: number;
  sid: number;
  invokeScene: number;
  supportedCompressTypes: number[];
  harmonyDeviceParams: HarmonyDeviceParams;
}

export default class HapProbeAbility extends UIAbility {
  private report: Report = { finished: false, run: '', steps: [] };
  private encoder: util.TextEncoder = new util.TextEncoder();
  private base64: util.Base64Helper = new util.Base64Helper();

  onCreate(): void {
    this.runProbe().catch((error: BusinessError) => {
      this.record('probe', false, error.code || -1, error.message);
    });
  }

  private save(name: string, contents: string): void {
    const f = fs.openSync(`${this.context.filesDir}/${name}`,
      fs.OpenMode.CREATE | fs.OpenMode.WRITE_ONLY | fs.OpenMode.TRUNC);
    try {
      fs.writeSync(f.fd, contents);
    } finally {
      fs.closeSync(f);
    }
  }

  private record(name: string, ok: boolean, code: number, detail: string): void {
    this.report.steps.push({ name: name, ok: ok, code: code, detail: detail });
    this.save('report.json', JSON.stringify(this.report, null, 2));
    hilog.info(0x0001, 'HapProbe', '%{public}s ok=%{public}s code=%{public}d', name, String(ok), code);
  }

  private eccOptions(purpose: number): huks.HuksOptions {
    return { properties: [
      { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huks.HuksKeyAlg.HUKS_ALG_ECC },
      { tag: huks.HuksTag.HUKS_TAG_KEY_SIZE, value: huks.HuksKeySize.HUKS_ECC_KEY_SIZE_256 },
      { tag: huks.HuksTag.HUKS_TAG_PURPOSE, value: purpose },
      { tag: huks.HuksTag.HUKS_TAG_DIGEST, value: huks.HuksKeyDigest.HUKS_DIGEST_SHA256 }
    ] };
  }

  private hmacOptions(): huks.HuksOptions {
    return { properties: [
      { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huks.HuksKeyAlg.HUKS_ALG_HMAC },
      { tag: huks.HuksTag.HUKS_TAG_KEY_SIZE, value: 256 },
      { tag: huks.HuksTag.HUKS_TAG_PURPOSE, value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_MAC },
      { tag: huks.HuksTag.HUKS_TAG_DIGEST, value: huks.HuksKeyDigest.HUKS_DIGEST_SHA256 }
    ] };
  }

  private base64Url(data: Uint8Array): string {
    return this.base64.encodeToStringSync(data, util.Type.BASIC_URL_SAFE).replace(/=+$/, '');
  }

  private decodeJson<T>(encoded: string): T {
    const bytes = this.base64.decodeSync(encoded, util.Type.BASIC);
    return JSON.parse(new util.TextDecoder().decodeWithStream(bytes)) as T;
  }

  private writeUint32LE(output: Uint8Array, offset: number, value: number): number {
    output[offset] = value & 0xff;
    output[offset + 1] = (value >>> 8) & 0xff;
    output[offset + 2] = (value >>> 16) & 0xff;
    output[offset + 3] = (value >>> 24) & 0xff;
    return offset + 4;
  }

  private writeField(output: Uint8Array, offset: number, value: Uint8Array): number {
    let next = this.writeUint32LE(output, offset, value.length);
    output.set(value, next);
    return next + value.length;
  }

  private wrappedImportBlob(kekEncoded: string, accessKey: string, wrappedEncoded: string): Uint8Array {
    const kek = this.decodeJson<TsmsKek>(kekEncoded);
    const kekBytes = this.base64.decodeSync(kek.key, util.Type.BASIC);
    const wrapped = this.base64.decodeSync(wrappedEncoded, util.Type.BASIC);
    if (kekBytes.length !== 91 + 12 + 32 + 16) {
      throw new ProbeError(-1, `Unexpected KEK bytes ${kekBytes.length}`);
    }
    if (wrapped.length !== 12 + 32 + 16) {
      throw new ProbeError(-1, `Unexpected wrapped key bytes ${wrapped.length}`);
    }
    const temporaryPublicKey = kekBytes.subarray(0, 91);
    const kekIv = kekBytes.subarray(91, 103);
    const kekCiphertext = kekBytes.subarray(103, 135);
    const kekTag = kekBytes.subarray(135);
    const aad = this.encoder.encodeInto(accessKey);
    const keyIv = wrapped.subarray(0, 12);
    const keyCiphertext = wrapped.subarray(12, wrapped.length - 16);
    const keyTag = wrapped.subarray(wrapped.length - 16);
    const keyLength = new Uint8Array(4);
    this.writeUint32LE(keyLength, 0, 32);
    const fields: Uint8Array[] = [
      temporaryPublicKey, aad, kekIv, kekTag, kekCiphertext,
      aad, keyIv, keyTag, keyLength, keyCiphertext
    ];
    let size = 0;
    for (const field of fields) size += 4 + field.length;
    const output = new Uint8Array(size);
    let offset = 0;
    for (const field of fields) offset = this.writeField(output, offset, field);
    if (offset !== output.length) throw new ProbeError(-1, 'Wrapped-key blob length mismatch');
    return output;
  }

  private async deleteIfPresent(alias: string): Promise<void> {
    try {
      if (await this.keyExists(alias)) {
        await huks.deleteKeyItem(alias, { properties: [] });
      }
    } catch (_) {
    }
  }

  private async keyExists(alias: string): Promise<boolean> {
    try {
      return await huks.isKeyItemExist(alias, { properties: [] });
    } catch (_) {
      return false;
    }
  }

  private async importWrappedKey(target: string, unwrap: string, options: huks.HuksOptions,
    blob: Uint8Array): Promise<void> {
    await this.deleteIfPresent(target);
    const properties = options.properties || [];
    properties.push({
      tag: huks.HuksTag.HUKS_TAG_UNWRAP_ALGORITHM_SUITE,
      value: huks.HuksUnwrapSuite.HUKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NOPADDING
    });
    options.properties = properties;
    options.inData = blob;
    await huks.importWrappedKeyItem(target, unwrap, options);
  }

  private async fetchHarmonyFiles(sk: string, accessKey: string): Promise<void> {
    const method = 'client.fetchHarmonyFiles';
    const timestamp = String(Date.now());
    const signature = await this.sign(sk, this.hmacOptions(),
      this.encoder.encodeInto(`${method}${timestamp}`));
    const body: HarmonyFetchBody = {
      deviceIdType: '10',
      harmonyDeviceType: 'phone',
      serviceType: 80,
      phoneType: 'VYG-AL30',
      abis: 'arm64-v8a',
      recommendSwitch: 1,
      model: 'VYG-AL30',
      marketName: '*',
      clientPackage: 'com.huawei.hmsapp.appgallery',
      timeZone: 'Asia/Shanghai',
      accountZone: 'CN',
      issueZone: 'cn',
      density: 560,
      locale: 'zh_Hans',
      singleHarmonyClient: '1',
      net: 1,
      ts: Number(timestamp),
      code: '0200',
      harmonyInfo: {
        harmonyApiLevel: 24,
        harmonyReleaseType: 'Release',
        hmosApiLevel: 60101,
        hmosReleaseType: 'Release',
        arkSupport: 1,
        arkMinVersion: 2,
        arkMaxVersion: 402653184,
        harmonyDeviceType: 'phone',
        glVersion: 'Maleoon.V360.6721605bb6c8da9cf2e35309cc57d25c1fcc6921',
        compatibleDeviceTypes: [],
        deviceFeatures: '',
        ohMinorApiVersion: 0,
        ohPatchApiVersion: 0
      },
      containerInfo: { firmwareVersion: '', emuiApiLevel: 0 },
      isSubUser: 0,
      manufacturer: 'HUAWEI',
      brand: 'HUAWEI',
      runMode: 2,
      deviceId: '*',
      clientCapability: '111111111111110101111101110111',
      pcEmulator: 0,
      clientVersion: '7.7.1',
      clientVersionCode: '1470701300',
      deviceHomeCountry: 'CN',
      apsid: timestamp,
      oaid: '*',
      screenInfo: '',
      osAccountId: 100,
      businessMode: 0,
      deviceRiskScore: 10,
      sid: Number(timestamp),
      invokeScene: 0,
      supportedCompressTypes: [1, 2],
      harmonyDeviceParams: {
        country: [],
        deviceTypes: ['phone'],
        apps: 'com.ss.hm.article.news'
      }
    };
    const request = http.createHttp();
    try {
      const url = `https://store-drcn.hispace.dbankcloud.com/hwmarket/harmony/client?method=${method}&ts=${timestamp}`;
      const response = await request.request(url, {
        method: http.RequestMethod.POST,
        header: {
          'charset': 'UTF-8',
          'user-agent': 'AppGallery##7.7.1.300##HUAWEI##VYG-AL30',
          'content-type': 'application/json;charset=utf-8',
          'X-Authorization': '{}',
          'x-msg-signature': this.base64.encodeToStringSync(signature),
          'x-msg-ak': accessKey
        },
        extraData: JSON.stringify(body),
        expectDataType: http.HttpDataType.STRING,
        connectTimeout: 15000,
        readTimeout: 30000
      });
      const result = String(response.result);
      this.save('harmony-response.json', result);
      let rtnCode = 'unparsed';
      try {
        const parsed = JSON.parse(result) as Record<string, Object>;
        rtnCode = String(parsed['rtnCode']);
      } catch (_) {
      }
      this.record('fetch-harmony-files', response.responseCode === 200 && rtnCode === '0', response.responseCode,
        `rtnCode=${rtnCode}; responseBytes=${result.length}; raw response kept in private app storage`);
    } finally {
      request.destroy();
    }
  }

  private async tsmsCredentialProbe(): Promise<void> {
    // The old AppGallery SDK uses its own bundle name as the registered TSMS kit name.
    // Our attestation certificate still identifies cn.rickytan.netcap, allowing this
    // probe to verify whether the server checks the claimed name against the certificate.
    const claimedKit = 'com.huawei.hmsapp.appgallery';
    const at = `hap_probe_tsms_at_${this.report.run}`;
    const uw = `hap_probe_tsms_uw_${this.report.run}`;
    const sk = 'hap_probe_tsms_sk';
    const dk = 'hap_probe_tsms_dk';
    const generated: string[] = [];
    try {
      const atOptions = this.eccOptions(huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN |
        huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY);
      await huks.generateKeyItem(at, atOptions);
      generated.push(at);
      const uwOptions = this.eccOptions(huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_UNWRAP);
      await huks.generateKeyItem(uw, uwOptions);
      generated.push(uw);
      const attestOptions: huks.HuksOptions = { properties: [
        { tag: huks.HuksTag.HUKS_TAG_ATTESTATION_CHALLENGE, value: this.encoder.encodeInto(String(Date.now())) },
        { tag: huks.HuksTag.HUKS_TAG_ATTESTATION_ID_ALIAS, value: this.encoder.encodeInto(at) },
        { tag: huks.HuksTag.HUKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, value: this.encoder.encodeInto('sec_level') }
      ] };
      const attestation = await huks.anonAttestKeyItem(at, attestOptions);
      const chain = attestation.certChains || [];
      if (chain.length !== 3) throw new ProbeError(-1, `Unexpected certificate count ${chain.length}`);
      const exported = await huks.exportKeyItem(uw, uwOptions);
      if (!exported.outData) throw new ProbeError(-1, 'No unwrap public key returned');

      const header: TsmsHeader = {
        cty: 'anon_cert',
        alg: 'ED256',
        kid: this.base64.encodeToStringSync(this.encoder.encodeInto(JSON.stringify({ len: 32 }))),
        x5c: chain
      };
      const payload: TsmsPayload = {
        packageName: claimedKit,
        appId: '',
        pbk: this.base64.encodeToStringSync(exported.outData),
        alg: 6,
        kekAlg: 2,
        akskVersion: 1,
        dkAlgLen: 1
      };
      const unsigned = `${this.base64Url(this.encoder.encodeInto(JSON.stringify(header)))}.` +
        this.base64Url(this.encoder.encodeInto(JSON.stringify(payload)));
      const signature = await this.sign(at, this.eccOptions(huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN),
        this.encoder.encodeInto(unsigned));
      const envelope: TsmsEnvelope = { request: `${unsigned}.${this.base64Url(signature)}` };
      const requestId = util.generateRandomUUID();
      const callTime = String(Date.now());
      const request = http.createHttp();
      try {
        const response = await request.request('https://tsms-drcn.security.dbankcloud.cn/tsms/v2/credentials', {
          method: http.RequestMethod.POST,
          header: {
            'Content-Type': 'application/json;charset=UTF-8',
            'X-ApplyCredential-Terminal': 'OUCS-ANON_CERT',
            'X-Request-ID': requestId,
            'X-App-ID': '',
            'X-RequestContext': `appPkgName=${claimedKit},callTime=${callTime}`,
            'X-Client-Version': 'OUCS 1.0.4-310'
          },
          extraData: JSON.stringify(envelope),
          expectDataType: http.HttpDataType.STRING,
          connectTimeout: 15000,
          readTimeout: 30000
        });
        const body = String(response.result);
        if (response.responseCode < 200 || response.responseCode >= 300) {
          this.save('tsms-error-response.json', body);
        }
        this.record('tsms-credential-request', response.responseCode >= 200 && response.responseCode < 300,
          response.responseCode, `responseBytes=${body.length}; successful credential retained in memory only`);
        if (response.responseCode >= 200 && response.responseCode < 300) {
          const credential = JSON.parse(body) as TsmsCredentialResponse;
          await this.importWrappedKey(sk, uw, this.hmacOptions(),
            this.wrappedImportBlob(credential.kek, credential.accessKey, credential.secretKey));
          generated.push(sk);
          this.record('import-sk', await huks.isKeyItemExist(sk, { properties: [] }), 0,
            'TSMS HMAC key imported into HUKS');
          const aesOptions: huks.HuksOptions = { properties: [
            { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huks.HuksKeyAlg.HUKS_ALG_AES },
            { tag: huks.HuksTag.HUKS_TAG_KEY_SIZE, value: huks.HuksKeySize.HUKS_AES_KEY_SIZE_256 },
            { tag: huks.HuksTag.HUKS_TAG_PURPOSE,
              value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT },
            { tag: huks.HuksTag.HUKS_TAG_BLOCK_MODE, value: huks.HuksCipherMode.HUKS_MODE_GCM },
            { tag: huks.HuksTag.HUKS_TAG_PADDING, value: huks.HuksKeyPadding.HUKS_PADDING_NONE }
          ] };
          await this.importWrappedKey(dk, uw, aesOptions,
            this.wrappedImportBlob(credential.kek, credential.accessKey, credential.dataKey));
          generated.push(dk);
          this.record('import-dk', await huks.isKeyItemExist(dk, { properties: [] }), 0,
            'TSMS data key imported into HUKS');
          const timestamp = String(Date.now());
          const signed = await this.sign(sk, this.hmacOptions(),
            this.encoder.encodeInto(`client.fetchHarmonyFiles${timestamp}`));
          this.record('sign-store-request', signed.length === 32, 0,
            `signatureBytes=${signed.length}; timestamp=${timestamp}; accessKeyBytes=${credential.accessKey.length}`);
          await this.fetchHarmonyFiles(sk, credential.accessKey);
        }
      } finally {
        request.destroy();
      }
    } catch (error) {
      const e = error as BusinessError;
      this.record('tsms-credential-request', false, e.code || -1, e.message);
    } finally {
      for (const alias of generated) {
        try {
          await huks.deleteKeyItem(alias, { properties: [] });
        } catch (_) {
        }
      }
      const remains = await this.keyExists(sk) || await this.keyExists(dk);
      this.record('cleanup-tsms-keys', !remains, 0, remains ? 'Imported key remains' : 'Imported keys deleted');
    }
  }

  private async sign(alias: string, options: huks.HuksOptions, data: Uint8Array): Promise<Uint8Array> {
    const session = await huks.initSession(alias, options);
    try {
      const result = await huks.finishSession(session.handle, { properties: options.properties, inData: data });
      if (!result.outData) throw new Error('No signature returned');
      return result.outData;
    } catch (error) {
      await huks.abortSession(session.handle, { properties: [] }).catch(() => {});
      const e = error as BusinessError;
      throw new ProbeError(e.code || -1, e.message);
    }
  }

  private async attest(alias: string, variant: string, extra: huks.HuksParam[]): Promise<void> {
    try {
      const props: huks.HuksParam[] = [
        { tag: huks.HuksTag.HUKS_TAG_ATTESTATION_CHALLENGE, value: this.encoder.encodeInto(this.report.run) },
        { tag: huks.HuksTag.HUKS_TAG_ATTESTATION_ID_ALIAS, value: this.encoder.encodeInto(alias) }
      ];
      const result = await huks.anonAttestKeyItem(alias, { properties: props.concat(extra) });
      const chain = result.certChains || [];
      // Public certificates stay in the debug application's sandbox, never logs.
      for (let i = 0; i < chain.length; i++) this.save(`${variant}-cert-${i}.txt`, chain[i]);
      this.record(`attest-${variant}`, chain.length > 0, 0, `certificateCount=${chain.length}`);
    } catch (error) {
      const e = error as BusinessError;
      this.record(`attest-${variant}`, false, e.code || -1, e.message);
    }
  }

  private async runProbe(): Promise<void> {
    this.report.run = util.generateRandomUUID();
    try {
      fs.unlinkSync(`${this.context.filesDir}/tsms-response.json`);
    } catch (_) {
    }
    const ecc = `hap_probe_ecc_${this.report.run}`;
    const mac = `hap_probe_mac_${this.report.run}`;
    const aliases: string[] = [];
    this.record('start', true, 0, 'Fresh probe keys only; existing AppGallery keys and private data are not accessed.');
    try {
      try {
        await huks.generateKeyItem(ecc, this.eccOptions(huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN |
          huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY));
        aliases.push(ecc);
        this.record('generate-ecc', true, 0, 'P-256 key created');
        await this.attest(ecc, 'public', []);
        await this.attest(ecc, 'security-level', [
          { tag: huks.HuksTag.HUKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, value: this.encoder.encodeInto('sec_level') }
        ]);
        const data = this.encoder.encodeInto(`hap-probe:${this.report.run}`);
        const signature = await this.sign(ecc, this.eccOptions(huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN), data);
        this.save('ecc-signature.base64', this.base64.encodeToStringSync(signature));
        this.save('ecc-message.txt', `hap-probe:${this.report.run}`);
        this.record('sign-ecc', signature.length > 0, 0, `signatureBytes=${signature.length}`);
      } catch (error) {
        const e = error as BusinessError;
        this.record('ecc', false, e.code || -1, e.message);
      }
      try {
        await huks.generateKeyItem(mac, this.hmacOptions());
        aliases.push(mac);
        const data = this.encoder.encodeInto('client.fetchHarmonyFiles1729382400000');
        const first = this.base64.encodeToStringSync(await this.sign(mac, this.hmacOptions(), data));
        const second = this.base64.encodeToStringSync(await this.sign(mac, this.hmacOptions(), data));
        const other = this.base64.encodeToStringSync(await this.sign(mac, this.hmacOptions(), this.encoder.encodeInto('different')));
        this.record('hmac-sha256', first.length === 44 && first === second && first !== other, 0,
          'Own generated key: repeated input matches; changed input differs. No TSMS credential was requested.');
      } catch (error) {
        const e = error as BusinessError;
        this.record('hmac-sha256', false, e.code || -1, e.message);
      }
      await this.tsmsCredentialProbe();
    } finally {
      for (const alias of aliases) {
        try {
          await huks.deleteKeyItem(alias, { properties: [] });
          this.record('cleanup', true, 0, 'Probe key deleted');
        } catch (error) {
          const e = error as BusinessError;
          this.record('cleanup', false, e.code || -1, alias);
        }
      }
      this.report.finished = true;
      this.save('report.json', JSON.stringify(this.report, null, 2));
      hilog.info(0x0001, 'HapProbe', 'finished');
      await this.context.terminateSelf();
    }
  }
}
