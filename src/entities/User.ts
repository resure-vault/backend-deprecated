import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from 'typeorm'
import { Secret } from './Secret'
import { APIKey } from './APIKey'

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id!: number

  @Column({ default: 'Unknown User' })
  name!: string

  @Column({ unique: true })
  email!: string

  @Column({ name: 'password' })
  password!: string

  @Column({ name: 'master_password_hash', nullable: true })
  masterPasswordHash?: string

  @OneToMany(() => Secret, s => s.user)
  secrets!: Secret[]

  @OneToMany(() => APIKey, k => k.user)
  api_keys!: APIKey[]
}
