/*
 * resure — the best way to store your secrets instead of forgetting them.
 *
 * Copyright (c) 2025-present
 * Shubham Yadav (bas3line), Nandha (almightynan)
 * License: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

// entities index
// consolidated typeorm entities used by the app
// includes: User, Secret, APIKey (see individual files for field details)
// these classes map directly to db tables and are used by repositories
// small note: treat these as the single source of truth for schema in the app

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
