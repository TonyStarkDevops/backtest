package com.kalado.user;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;

import com.kalado.common.dto.userDto;
import com.kalado.common.exception.CustomException;
import com.kalado.common.feign.authentication.AuthenticationApi;
import com.kalado.user.adapters.repository.userRepository;
import com.kalado.user.domain.model.user;
import com.kalado.user.service.userService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

@SpringBootTest
class userServiceIntegrationTest {

  @Autowired
  private userRepository userRepository;

  @Autowired
  private userService userService;

  @MockBean
  private AuthenticationApi authenticationApi;

  private userDto userDto;

  @BeforeEach
  void setUp() {
    userRepository.deleteAll();

    userDto = userDto.builder()
            .id(1L)
            .firstName("FIRSTNAME")
            .lastName("LASTNAME")
            .address("ADDRESS")
            .username("USERNAME")
            .phoneNumber("PHONE_NUMBER")
            .build();
  }

  @Test
  void modifyProfile_ShouldReturnTrue_WhenuserExists() {
    user initialuser = user.builder()
            .id(1L)
            .firstName("OLD_FIRSTNAME")
            .lastName("OLD_LASTNAME")
            .address("OLD_ADDRESS")
            .phoneNumber("OLD_PHONE_NUMBER")
            .build();
    userRepository.save(initialuser);

    Boolean result = userService.modifyProfile(1L, userDto);

    user modifieduser = userRepository.findById(1L).orElse(null);

    assertTrue(result);
    assertNotNull(modifieduser);
    assertEquals(userDto.getFirstName(), modifieduser.getFirstName());
    assertEquals(userDto.getLastName(), modifieduser.getLastName());
    assertEquals(userDto.getAddress(), modifieduser.getAddress());
    assertEquals(userDto.getPhoneNumber(), modifieduser.getPhoneNumber());
  }

  @Test
  void createuser_ShouldSaveuser() {
    userService.createuser(userDto);

    user saveduser = userRepository.findById(1L).orElse(null);

    assertNotNull(saveduser);
    assertEquals(userDto.getId(), saveduser.getId());
    assertEquals(userDto.getFirstName(), saveduser.getFirstName());
    assertEquals(userDto.getLastName(), saveduser.getLastName());
    assertEquals(userDto.getAddress(), saveduser.getAddress());
    assertEquals(userDto.getPhoneNumber(), saveduser.getPhoneNumber());
  }

  @Test
  void getuserAddress_ShouldReturnAddress_WhenuserExists() {
    user user = user.builder()
            .id(1L)
            .firstName("FIRSTNAME")
            .lastName("LASTNAME")
            .address("ADDRESS")
            .phoneNumber("PHONE_NUMBER")
            .build();
    userRepository.save(user);

    String address = userService.getuserAddress(1L);

    assertEquals("ADDRESS", address);
  }

  @Test
  void getUserProfile_ShouldReturnuserDto_WhenuserExists() {
    user user = user.builder()
            .id(1L)
            .firstName("FIRSTNAME")
            .lastName("LASTNAME")
            .address("ADDRESS")
            .phoneNumber("PHONE_NUMBER")
            .build();
    userRepository.save(user);
    Mockito.when(authenticationApi.getUsername(any())).thenReturn("USERNAME");

    userDto result = userService.getUserProfile(1L);

    assertNotNull(result);
    assertEquals(user.getId(), result.getId());
    assertEquals(user.getFirstName(), result.getFirstName());
    assertEquals(user.getLastName(), result.getLastName());
    assertEquals(user.getAddress(), result.getAddress());
    assertEquals(user.getPhoneNumber(), result.getPhoneNumber());
  }

  @Test
  void getUserProfile_ShouldThrowCustomException_WhenuserDoesNotExist() {
    Mockito.when(authenticationApi.getUsername(any())).thenReturn("USERNAME");

    Exception exception = assertThrows(CustomException.class, () -> {
      userService.getUserProfile(2L);
    });

    assertEquals("user not found", exception.getMessage());
  }
}
