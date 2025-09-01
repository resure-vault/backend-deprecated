// Dynamically import Entities and config so ts-node/esm can resolve .ts modules when TypeORM CLI runs
const entitiesModule = await import('./entities/Entities.ts')
const configModule = await import('./config.ts')
import { DataSource } from 'typeorm'

const { User, Secret, APIKey } = entitiesModule
const { config } = configModule

const AppDataSource = new DataSource({
  type: 'postgres',
  url: config.DATABASE_URL,
  schema: config.DB_SCHEMA,
  synchronize: false,
  logging: false,
  entities: [User, Secret, APIKey],
})

export default AppDataSource
