import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToMany,
  ManyToOne,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  Index,
} from 'typeorm'

// Use explicit table names to match the Go/Postgres schema (plural snake_case)

@Entity({ name: 'users' })
export class User {
  @PrimaryGeneratedColumn()
  id!: number

  @Column({ default: 'Unknown User' })
  name!: string

  @Index({ unique: true })
  @Column()
  email!: string

  @Column({ name: 'password' })
  password!: string

  @Column({ name: 'master_password_hash', nullable: true })
  masterPasswordHash?: string

  @CreateDateColumn({ name: 'created_at', type: 'timestamp', default: () => 'now()' })
  createdAt!: Date

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamp', default: () => 'now()' })
  updatedAt!: Date

  @OneToMany(() => Secret, (s: any) => s.user)
  secrets!: Secret[]

  @OneToMany(() => APIKey, (k: any) => k.user)
  api_keys!: APIKey[]
}

@Entity({ name: 'secrets' })
export class Secret {
  @PrimaryGeneratedColumn()
  id!: number

  @Index()
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

  @CreateDateColumn({ name: 'created_at', type: 'timestamp', default: () => 'now()' })
  createdAt!: Date

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamp', default: () => 'now()' })
  updatedAt!: Date

  @ManyToOne(() => User, (u: any) => u.secrets)
  user!: User
}

@Entity({ name: 'api_keys' })
export class APIKey {
  @PrimaryGeneratedColumn()
  id!: number

  @Index()
  @Column({ name: 'user_id' })
  userId!: number

  @Column()
  name!: string

  @Index({ unique: true })
  @Column()
  key!: string

  @Column({ name: 'is_active', default: true })
  isActive!: boolean

  @Column({ name: 'last_used', type: 'timestamp', nullable: true })
  lastUsed?: Date | null

  @CreateDateColumn({ name: 'created_at', type: 'timestamp', default: () => 'now()' })
  createdAt!: Date

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamp', default: () => 'now()' })
  updatedAt!: Date

  @DeleteDateColumn({ name: 'deleted_at', nullable: true })
  deletedAt?: Date | null

  @ManyToOne(() => User, (u: any) => u.api_keys)
  user!: User
}
