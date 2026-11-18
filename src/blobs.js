import fs from 'node:fs'
import path from 'node:path'
import { dataDir } from './paths.js'

function blobDir () {
  return path.join(dataDir(), 'blobs')
}

export function writeBlob (name, payload) {
  const directory = blobDir()
  fs.mkdirSync(directory, { recursive: true })
  const file = path.join(directory, name)
  fs.writeFileSync(file, JSON.stringify(payload))
  return file
}

export function readBlob (file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

export function removeBlob (file) {
  if (file && fs.existsSync(file)) fs.unlinkSync(file)
}
