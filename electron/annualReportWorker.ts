import { parentPort, workerData } from 'worker_threads'
import { wcdbService } from './services/wcdbService'
import { annualReportService } from './services/annualReportService'

interface WorkerConfig {
  year: number
  dbPath: string
  wcdbKeys: Record<string, string>
  myWxid: string
  resourcesPath?: string
  userDataPath?: string
  logEnabled?: boolean
}

const config = workerData as WorkerConfig
process.env.WEFLOW_WORKER = '1'
if (config.resourcesPath) {
  process.env.WCDB_RESOURCES_PATH = config.resourcesPath
}

wcdbService.setPaths(config.resourcesPath || '', config.userDataPath || '')
wcdbService.setLogEnabled(config.logEnabled === true)

async function run() {
  wcdbService.setWcdbKeys(config.wcdbKeys || {})
  const result = await annualReportService.generateReportWithConfig({
    year: config.year,
    dbPath: config.dbPath,
    wcdbKeys: config.wcdbKeys || {},
    wxid: config.myWxid,
    onProgress: (status: string, progress: number) => {
      parentPort?.postMessage({
        type: 'annualReport:progress',
        data: { status, progress }
      })
    }
  })

  parentPort?.postMessage({ type: 'annualReport:result', data: result })
}

run().catch((err) => {
  parentPort?.postMessage({ type: 'annualReport:error', error: String(err) })
})
