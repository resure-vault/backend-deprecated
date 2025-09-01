import express from 'express'
import { APIKeysController } from '../controllers/apikeys'

const router = express.Router()
const ctl = new APIKeysController()

router.get('/', ctl.list.bind(ctl))
router.post('/', ctl.create.bind(ctl))
router.put('/:id', ctl.create.bind(ctl))
router.delete('/:id', ctl.revoke.bind(ctl))

export default router
