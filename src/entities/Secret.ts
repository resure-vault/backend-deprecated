import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm'
import { User } from './User'

@Entity()
export class Secret {
  @PrimaryGeneratedColumn()
  id!: number

  @Column({ name: 'user_id' })
  userId!: number

  @Column()
  name!: string

  @Column()
  value!: string

  @Column({ default: 'General' })
  category!: string

  @Column({ nullable: true })
  description?: string

  @ManyToOne(() => User, u => u.secrets)
  user!: User
}
