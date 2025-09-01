import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm'
import { User } from './User'

@Entity()
export class APIKey {
  @PrimaryGeneratedColumn()
  id!: number

  @Column({ name: 'user_id' })
  userId!: number

  @Column()
  name!: string

  @Column()
  key!: string

  @Column({ default: true })
  isActive!: boolean

  @Column({ type: 'timestamp', nullable: true })
  lastUsed?: Date | null

  @ManyToOne(() => User, u => u.api_keys)
  user!: User
}
