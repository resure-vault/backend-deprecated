import AppDataSource from './data-source'
import { User } from './entities/Entities'
import { createUser } from './services/userService'

async function seed() {
  await AppDataSource.initialize()
  const exists = await AppDataSource.getRepository(User).findOneBy({ email: 'admin@example.com' })
  if (!exists) {
    console.log('creating admin user')
    await createUser('Admin', 'admin@example.com', 'adminpass')
  } else {
    console.log('admin exists')
  }
  process.exit(0)
}

seed().catch(err => {
  console.error(err)
  process.exit(1)
})
