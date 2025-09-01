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
