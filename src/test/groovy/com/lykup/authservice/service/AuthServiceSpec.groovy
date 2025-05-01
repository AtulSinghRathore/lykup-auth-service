package com.lykup.authservice.service

import com.lykup.authservice.dto.LoginRequest
import com.lykup.authservice.dto.SignupRequest
import com.lykup.authservice.entity.User
import com.lykup.authservice.repository.UserRepository
import com.lykup.authservice.security.JwtUtil
import com.lykup.authservice.service.AuthService
import org.springframework.security.crypto.password.PasswordEncoder
import spock.lang.Specification

class AuthServiceSpec extends Specification {
//

    def userRepository = Mock(UserRepository)
    def passwordEncoder = Mock(PasswordEncoder)
    def jwtUtil = Mock(JwtUtil)
    def authService = new AuthService(userRepository, passwordEncoder, jwtUtil)

    def "should register user successfully"() {
        given:
        def request = new SignupRequest(username: 'testuser', email: 'test@example.com', password: 'pass123')

        when:
        authService.registerUser(request)

        then:
        1 * userRepository.existsByEmail('test@example.com') >> false
        1 * userRepository.existsByUsername('testuser') >> false
        1 * passwordEncoder.encode('pass123') >> 'encoded'
        1 * userRepository.save(_ as User)
    }

    def "should throw error if user email exists"() {
        given:
        def request = new SignupRequest(username: 'testuser', email: 'test@example.com', password: 'pass123')

        when:
        authService.registerUser(request)

        then:
        1 * userRepository.existsByEmail('test@example.com') >> true
        thrown(RuntimeException)
    }

    def "should authenticate user and return token"() {
        given:
        def loginRequest = new LoginRequest(email: 'test@example.com', password: 'pass123')
        def user = new User(id: UUID.randomUUID(), email: 'test@example.com', username: 'testuser', passwordHash: 'encoded')

        when:
        def result = authService.authenticateUser(loginRequest)

        then:
        1 * userRepository.findByEmail('test@example.com') >> Optional.of(user)
        1 * passwordEncoder.matches('pass123', 'encoded') >> true
        1 * jwtUtil.generateToken(user.id.toString(), 'testuser') >> 'fake-jwt-token'

        result.token == 'fake-jwt-token'
        result.username == 'testuser'
    }
}
