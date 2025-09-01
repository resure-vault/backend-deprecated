import express from 'express'
import { SecretsController } from '../controllers/secrets'

const router = express.Router()
const ctl = new SecretsController()

router.get('/', ctl.list.bind(ctl))
router.post('/', ctl.create.bind(ctl))
router.get('/:id', ctl.get.bind(ctl))
router.put('/:id', ctl.update.bind(ctl))
router.delete('/:id', ctl.delete.bind(ctl))

export default router
